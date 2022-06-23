import contextlib
import http.client
import logging
import re
import socket
import ssl
import sys

from ..dependencies import (
    urllib3,
    requests,
    brotli
)

if urllib3 is None or requests is None:
    raise ImportError

from urllib3.util import parse_url
import urllib3.connection
import urllib3.exceptions
from urllib3.util.ssl_ import create_urllib3_context

import requests.utils
import requests.adapters


from .common import (
    Response,
    BackendRH
)
from ..socks import (
    sockssocket,
    ProxyError as SocksProxyError
)
from .utils import (
    ssl_load_certs,
    socks_create_proxy_args, select_proxy, get_redirect_method
)

from ..utils import (
    IncompleteRead,
    TransportError,
    SSLError,
    HTTPError,
    ProxyError,
    RequestError,
    UnsupportedRequest
)

from http.client import HTTPConnection

SUPPORTED_ENCODINGS = [
    'gzip', 'deflate'
]

# TODO: enforce a minimum version of requests and urllib3

urllib3_version = urllib3.__version__.split('.')
if len(urllib3_version) == 2:
    urllib3_version.append('0')
urllib3_version = tuple(map(int, urllib3_version[:3]))

requests_version = tuple(map(int, requests.__version__.split('.')))

# urllib3 does not support brotlicffi on versions < 1.26.9 [1], and brotli on < 1.25.1 [2]
# 1: https://github.com/urllib3/urllib3/blob/1.26.x/CHANGES.rst#1269-2022-03-16
# 2: https://github.com/urllib3/urllib3/blob/main/CHANGES.rst#1251-2019-04-24
if (brotli is not None
        and not (brotli.__name__ == 'brotlicffi' and urllib3_version < (1, 26, 9))
        and not (brotli.__name__ == 'brotli' and urllib3_version < (1, 25, 1))):
    SUPPORTED_ENCODINGS.append('br')

# requests < 2.24.0 always uses pyopenssl by default if installed.
# We do not support pyopenssl's ssl context, so we need to revert this.
# See: https://github.com/psf/requests/pull/5443
if requests_version < (2, 24, 0):
    with contextlib.suppress(ImportError, AttributeError):
        from urllib3.contrib import pyopenssl
        pyopenssl.extract_from_urllib3()

"""
Override urllib3's behavior to not convert lower-case percent-encoded characters
to upper-case during url normalization process.

RFC3986 defines that the lower or upper case percent-encoded hexidecimal characters are equivalent
and normalizers should convert them to uppercase for consistency [1].

However, some sites may have an incorrect implementation where they provide
a percent-encoded url that is then compared case-sensitively.[2]

While this is a very rare case, since urllib does not do this normalization step, it
is best to avoid it here too for compatability reasons.

1: https://tools.ietf.org/html/rfc3986#section-2.1
2: https://github.com/streamlink/streamlink/pull/4003
"""


class _Urllib3PercentREOverride:
    def __init__(self, r: re.Pattern):
        self.re = r

    # pass through all other attribute calls to the original re
    def __getattr__(self, item):
        return self.re.__getattribute__(item)

    def subn(self, repl, string, *args, **kwargs):
        return string, self.re.subn(repl, string, *args, **kwargs)[1]

    def findall(self, component, *args, **kwargs):
        return [c.upper() for c in self.re.findall(component, *args, **kwargs)]


if urllib3_version >= (1, 25, 4):
    # urllib3 >= 1.25.8 uses subn:
    # https://github.com/urllib3/urllib3/commit/a2697e7c6b275f05879b60f593c5854a816489f0
    # 1.25.4 <= urllib3 < 1.25.8 uses findall:
    # https://github.com/urllib3/urllib3/commit/5b047b645f5f93900d5e2fc31230848c25eb1f5f
    import urllib3.util.url
    urllib3.util.url.PERCENT_RE = _Urllib3PercentREOverride(urllib3.util.url.PERCENT_RE)

elif (1, 25, 0) <= urllib3_version < (1, 25, 4):
    # 1.25.0 <= urllib3 < 1.25.4 uses rfc3986 normalizers package:
    # https://github.com/urllib3/urllib3/commit/a74c9cfbaed9f811e7563cfc3dce894928e0221a
    # https://github.com/urllib3/urllib3/commit/0aa3e24fcd75f1bb59ab159e9f8adb44055b2271
    import urllib3.packages.rfc3986.normalizers as normalizers
    normalizers.PERCENT_MATCHER = _Urllib3PercentREOverride(normalizers.PERCENT_MATCHER)

"""
Workaround for issue in urllib.util.ssl_.py. ssl_wrap_context does not pass
server_hostname to SSLContext.wrap_socket if server_hostname is an IP,
however this is an issue because we set check_hostname to True in our SSLContext.

Monkey-patching IS_SECURETRANSPORT forces ssl_wrap_context to pass server_hostname regardless.

This has been fixed in urllib3 2.0, which is still in development.
See: https://github.com/urllib3/urllib3/issues/517
"""

if urllib3_version < (2, 0, 0):
    try:
        urllib3.util.IS_SECURETRANSPORT = urllib3.util.ssl_.IS_SECURETRANSPORT = True
    except AttributeError:
        pass


class RequestsHTTPResponseAdapter(Response):
    def __init__(self, res: requests.models.Response):
        super().__init__(
            raw=res, headers=res.headers, url=res.url,
            status=res.status_code, reason=res.reason)

    def read(self, amt: int = None):
        try:
            # Interact with urllib3 response directly.
            return self.raw.raw.read(amt, decode_content=True)
        # raw is an urllib3 HTTPResponse, so exceptions will be from urllib3
        except urllib3.exceptions.HTTPError as e:
            handle_urllib3_read_exceptions(e)
            raise TransportError(cause=e) from e


def find_original_error(e, err_types):
    if not isinstance(e, Exception):
        return
    return next(
        (err for err in (e, e.__cause__, *(e.args or [])) if
         isinstance(err, err_types)), None)


def handle_urllib3_read_exceptions(e):
    # Sometimes IncompleteRead is wrapped by urllib.exceptions.ProtocolError, so we have to check the args
    ic_read_err = find_original_error(e, (http.client.IncompleteRead, urllib3.exceptions.IncompleteRead))
    if ic_read_err is not None:
        raise IncompleteRead(partial=ic_read_err.partial, expected=ic_read_err.expected)
    if isinstance(e, urllib3.exceptions.SSLError):
        raise SSLError(cause=e) from e


class YDLRequestsHTTPAdapter(requests.adapters.HTTPAdapter):
    """
    Custom HTTP adapter to support passing SSLContext and other arguments to
    the underlying urllib3 PoolManager.
    """
    def __init__(self, ydl, ssl_context):
        self.ydl = ydl
        self._pm_args = {
            'ssl_context': ssl_context,
        }
        source_address = self.ydl.params.get('source_address')
        if source_address:
            self._pm_args['source_address'] = (source_address, 0)
        super().__init__(max_retries=urllib3.util.retry.Retry(False))

    def init_poolmanager(self, *args, **kwargs):
        return super().init_poolmanager(*args, **kwargs, **self._pm_args)

    def proxy_manager_for(self, *args, **kwargs):
        return super().proxy_manager_for(*args, **kwargs, **self._pm_args)

    def cert_verify(*args, **kwargs):
        # skip as using our SSLContext
        pass


class YDLRequestsSession(requests.sessions.Session):

    def rebuild_method(self, prepared_request, response):
        """
        Ensure unified redirect method handling with our urllib redirect handler.
        """
        prepared_request.method = get_redirect_method(prepared_request.method, response.status_code)


class YDLUrllib3LoggingFilter(logging.Filter):

    def filter(self, record):
        # Ignore HTTP request messages since http lib prints those
        if record.msg == '%s://%s:%s "%s %s %s" %s %s':
            return False
        return True


class RequestsRH(BackendRH):
    SUPPORTED_SCHEMES = ['http', 'https']

    def __init__(self, ydl):
        super().__init__(ydl)
        self._session = None
        if self._is_disabled:
            return

        if self.ydl.params.get('debug_printtraffic'):
            # Setting this globally is not ideal, but is easier than hacking with urllib3.
            # It could technically be problematic for scripts embedding yt-dlp.
            # However, it is unlikely debug traffic is used in that context in a way this will cause problems.
            HTTPConnection.debuglevel = 1

            # Print urllib3 debug messages
            logger = logging.getLogger('urllib3')
            handler = logging.StreamHandler(stream=sys.stdout)
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.addFilter(YDLUrllib3LoggingFilter())
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
        # this is expected if we are using --no-check-certificate
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @property
    def _is_disabled(self):
        return 'no-requests' in self.ydl.params.get('compat_opts', [])

    @property
    def session(self):
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def close(self):
        if self._session:
            self.session.close()

    def _create_session(self):
        session = YDLRequestsSession()
        _http_adapter = YDLRequestsHTTPAdapter(ydl=self.ydl, ssl_context=self.make_sslcontext())
        session.adapters.clear()
        session.headers = requests.models.CaseInsensitiveDict({'Connection': 'keep-alive'})
        session.mount('https://', _http_adapter)
        session.mount('http://', _http_adapter)
        session.cookies = self.cookiejar
        session.trust_env = False  # no need, we already load proxies from env
        return session

    def _make_sslcontext(self, verify, **kwargs):
        context = create_urllib3_context(cert_reqs=ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)
        if verify:
            # urllib3 < 2.0 always sets this to false, but we want it to be true when ssl.CERT_REQUIRED
            context.check_hostname = True
            ssl_load_certs(context, self.ydl.params)
        if urllib3_version < (1, 26, 0):
            # urllib3 <1.26.0 does not set ALPN, which is required by some sites (see urllib handler)
            with contextlib.suppress(NotImplementedError):
                context.set_alpn_protocols(['http/1.1'])
        return context

    def _prepare_request(self, request):
        if self._is_disabled:
            raise UnsupportedRequest('Not using requests backend as no-requests compat opt is set.')

        if request.proxies and 'no' in request.proxies:
            # NO_PROXY is buggy in requests.
            # Disable the handler for now until it is fixed, or we implement a workaround
            # See https://github.com/psf/requests/issues/5000 and related issues
            raise UnsupportedRequest('NO_PROXY not supported by requests backend')

        # Requests doesn't set content-type if we have already encoded the data, while urllib does.
        # We need to manually set it in this case as many extractors do not.
        if 'content-type' not in request.headers:
            if isinstance(request.data, (str, bytes)) or hasattr(request.data, 'read'):
                request.headers['content-type'] = 'application/x-www-form-urlencoded'

        if 'Accept-Encoding' not in request.headers:
            request.headers['Accept-Encoding'] = ', '.join(SUPPORTED_ENCODINGS)

        if not request.compression:
            del request.headers['accept-encoding']

        if self.ydl.params.get('no_persistent_connections', False) is True:
            request.headers['Connection'] = 'close'

    def handle(self, request):
        max_redirects_exceeded = False

        try:
            res = self.session.request(
                method=request.method,
                url=request.url,
                data=request.data,
                headers=request.headers,
                timeout=request.timeout,
                proxies=request.proxies,
                allow_redirects=True,
                stream=True
            )

        except requests.exceptions.TooManyRedirects as e:
            max_redirects_exceeded = True
            res = e.response
        except requests.exceptions.SSLError as e:
            raise SSLError(cause=e) from e
        except requests.exceptions.ProxyError as e:
            raise ProxyError(cause=e) from e
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Some urllib3 exceptions such as IncompleteRead are wrapped by ConnectionError on request
            handle_urllib3_read_exceptions(find_original_error(e, (urllib3.exceptions.HTTPError,)))
            raise TransportError(cause=e) from e
        except urllib3.exceptions.HTTPError as e:
            # Catch any urllib3 exceptions that may leak through
            handle_urllib3_read_exceptions(e)
            raise TransportError(cause=e) from e
        # Any misc Requests exception. May not necessary be network related e.g. InvalidURL
        except requests.exceptions.RequestException as e:
            raise RequestError(cause=e) from e
        requests_res = RequestsHTTPResponseAdapter(res)
        if not 200 <= requests_res.status < 300:
            raise HTTPError(requests_res, redirect_loop=max_redirects_exceeded)
        return requests_res


# Since we already have a socks proxy implementation,
# we can use that with urllib3 instead of requiring an extra dependency.
class SocksHTTPConnection(urllib3.connection.HTTPConnection):
    def __init__(self, _socks_options, *args, **kwargs):  # must use _socks_options to pass PoolKey checks
        self._proxy_args = _socks_options
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        sock = sockssocket()
        sock.setproxy(**self._proxy_args)
        if isinstance(self.timeout, (int, float)):
            sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except (socket.timeout, TimeoutError) as e:
            raise urllib3.exceptions.ConnectTimeoutError(self, f'Connection to {self.host} timed out. (connect timeout={self.timeout})') from e
        except SocksProxyError as e:
            raise urllib3.exceptions.ProxyError(str(e), e) from e
        except (OSError, socket.error) as e:
            raise urllib3.exceptions.NewConnectionError(self, f'Failed to establish a new connection: {e}') from e

        return sock


class SocksHTTPSConnection(SocksHTTPConnection, urllib3.connection.HTTPSConnection):
    pass


class SocksHTTPConnectionPool(urllib3.HTTPConnectionPool):
    ConnectionCls = SocksHTTPConnection


class SocksHTTPSConnectionPool(urllib3.HTTPSConnectionPool):
    ConnectionCls = SocksHTTPSConnection


class SocksProxyManager(urllib3.PoolManager):

    def __init__(self, socks_proxy, username=None, password=None, num_pools=10, headers=None, **connection_pool_kw):
        connection_pool_kw['_socks_options'] = socks_create_proxy_args(socks_proxy)
        super().__init__(num_pools, headers, **connection_pool_kw)
        self.pool_classes_by_scheme = {
            'http': SocksHTTPConnectionPool,
            'https': SocksHTTPSConnectionPool
        }


requests.adapters.SOCKSProxyManager = SocksProxyManager
requests.adapters.select_proxy = select_proxy
