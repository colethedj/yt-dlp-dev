import http.client
import logging
import socket
import ssl
import sys
from urllib.parse import urljoin

import urllib3
import requests.utils
from urllib3.util import parse_url
from urllib.request import _parse_proxy
from ..compat import (
    compat_brotli
)

from .common import (
    HTTPResponse,
    BackendRH,
    Request
)
from .socksproxy import (
    sockssocket,
    ProxyError as SocksProxyError
)
from .utils import (
    ssl_load_certs,
    socks_create_proxy_args, select_proxy
)

from ..utils import (
    IncompleteRead,
    TransportError,
    SSLError,
    HTTPError,
    ProxyError,
    RequestError
)

import requests.adapters
import requests
from urllib3.util.ssl_ import create_urllib3_context
import urllib3.connection
import urllib3.exceptions
from http.client import HTTPConnection

SUPPORTED_ENCODINGS = [
    'gzip', 'deflate'
]

# TODO: fix this for requests
# TODO: make it a requirement to have urllib3 >= 1.26.9
# urllib3 does not support brotlicffi on versions < 1.26.9
if compat_brotli and not (compat_brotli.__name__ == 'brotlicffi' and urllib3.__version__ < '1.26.9'):
    SUPPORTED_ENCODINGS.append('br')


class RequestsHTTPResponseAdapter(HTTPResponse):
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
        Make redirect method handling the same as YoutubeDLRedirectHandler.
        (requests by default turns all 302s, regardless of method, into GET)
        TODO: make a method used by this and YoutubeDLRedirectHandler
        """
        m = prepared_request.method
        # A 303 must either use GET or HEAD for subsequent request
        # https://datatracker.ietf.org/doc/html/rfc7231#section-6.4.4
        if response.status_code == 303 and m != 'HEAD':
            m = 'GET'
        # 301 and 302 redirects are commonly turned into a GET from a POST
        # for subsequent requests by browsers, so we'll do the same.
        # https://datatracker.ietf.org/doc/html/rfc7231#section-6.4.2
        # https://datatracker.ietf.org/doc/html/rfc7231#section-6.4.3
        if response.status_code in (301, 302) and m == 'POST':
            m = 'GET'

        prepared_request.method = m


class YDLUrllib3LoggingFilter(logging.Filter):

    def filter(self, record: logging.LogRecord) -> bool:
        # Ignore HTTP request messages since http lib prints those
        if record.msg == '%s://%s:%s "%s %s %s" %s %s':
            return False
        return True


class RequestsRH(BackendRH):
    SUPPORTED_SCHEMES = ['http', 'https']

    def __init__(self, ydl):
        super().__init__(ydl)
        self.session = self._create_session()
        if not self._is_force_disabled:
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

    @property
    def _is_force_disabled(self):
        # TODO: improve implementation and purpose
        if 'no-requests' in self.ydl.params.get('compat_opts', []):
            return True
        return False

    def _make_sslcontext(self, verify, **kwargs) -> ssl.SSLContext:
        context = create_urllib3_context(cert_reqs=ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)
        if verify:
            # urllib3 < 2.0 always sets this to false, but we want it to be true when ssl.CERT_REQUIRED
            context.check_hostname = True
            ssl_load_certs(context, self.ydl.params)
        return context

    @staticmethod
    def _sanitize_proxies(proxies: dict):
        # TODO: improve this
        proxies_new = proxies.copy()
        for key, proxy in proxies.items():
            try:
                proxy_parsed = parse_url(requests.utils.prepend_scheme_if_needed(proxy, 'http'))
                if not proxy_parsed.host and _parse_proxy(proxy)[0] is None:
                    proxy_parsed = parse_url(requests.utils.prepend_scheme_if_needed(f'http://{proxy}', 'http'))
            except urllib3.exceptions.LocationParseError:
                proxy_parsed = None
            if not proxy_parsed or not proxy_parsed.host:
                raise RequestError('Malformed proxy')
            proxies_new[key] = proxy_parsed.url
        return proxies_new

    def can_handle(self, request: Request) -> bool:
        if self._is_force_disabled:
            self.write_debug('Not using requests backend as no-requests compat opt is set.', only_once=True)
            return False
        if request.proxies and 'no' in request.proxies:
            # NO_PROXY is buggy in requests.
            # Disable the handler for now until it is fixed, or we implement a workaround
            # See https://github.com/psf/requests/issues/5000 and related issues
            return False
        try:
            self._sanitize_proxies(request.proxies)
        except RequestError:
            self.ydl.report_warning(
                'Check your proxy url; it is malformed and requests will not accept it. '
                'Proceeding to let another backend try to deal with it...', only_once=True)
            return False

        return super().can_handle(request)

    def handle(self, request: Request) -> HTTPResponse:
        headers = request.headers.copy()  # TODO: make a copy of request for each handler
        if 'Accept-Encoding' not in headers:
            headers['Accept-Encoding'] = ', '.join(SUPPORTED_ENCODINGS)

        if not request.compression:
            del headers['accept-encoding']

        if self.ydl.params.get('no_persistent_connections', False) is True:
            headers['Connection'] = 'close'

        max_redirects_exceeded = False
        try:
            res = self.session.request(
                method=request.method,
                url=request.url,
                data=request.data,
                headers=headers,
                timeout=request.timeout,
                proxies=self._sanitize_proxies(request.proxies),
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
            """
            Close the connection when finished instead of releasing it to the pool.
            May help with recovering from temporary errors related to persistent connections (e.g. temp block)
            """
            def release_conn_override():
                if hasattr(res.raw, '_connection') and res.raw._connection is not None:
                    res.raw._connection.close()
                    res.raw._connection = None
            res.raw.release_conn = release_conn_override
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

"""
Workaround for issue in urllib.util.ssl_.py. ssl_wrap_context does not pass 
server_hostname to SSLContext.wrap_socket if server_hostname is an IP, 
however this is an issue because we set check_hostname to True in our SSLContext.

Monkey-patching IS_SECURETRANSPORT forces ssl_wrap_context to pass server_hostname regardless.

This has been fixed in urllib3 2.0, which is still in development.
See https://github.com/urllib3/urllib3/issues/517 for more details
"""

if urllib3.__version__ < '2.0':
    try:
        urllib3.util.IS_SECURETRANSPORT = urllib3.util.ssl_.IS_SECURETRANSPORT = True
    except AttributeError:
        pass
