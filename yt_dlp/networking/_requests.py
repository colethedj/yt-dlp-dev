import http.client
import re
import ssl

import urllib3

from ..compat import (
    compat_brotli
)

from .common import (
    make_std_headers,
    HTTPResponse,
    BackendRH,
    Request,
    UniqueHTTPHeaderStore
)
from .socksproxy import (
    sockssocket,
    ProxyError as SocksProxyError
)
from .utils import (
    ssl_load_certs,
    socks_create_proxy_args
)

from ..utils import (
    IncompleteRead,
    TransportError,
    SSLError,
    HTTPError,
    ProxyError, urljoin, RequestError
)

import requests.adapters
from requests.cookies import merge_cookies
import requests
from urllib3.util.url import parse_url
from urllib3.util.ssl_ import create_urllib3_context
import urllib3.connection

SUPPORTED_ENCODINGS = [
    'gzip', 'deflate'
]

# TODO: fix this for requests
# TODO: make it a requirement to have urllib3 >= 1.26.9
# urllib3 does not support brotlicffi on versions < 1.26.9
if compat_brotli and not (compat_brotli.__name__ == 'brotlicffi' and urllib3.__version__ < '1.26.9'):
    SUPPORTED_ENCODINGS.append('br')


class RequestsResponseAdapter(HTTPResponse):
    def __init__(self, res: requests.models.Response):
        self._res = res
        self._url = res.url

        super().__init__(
            headers=res.headers, status=res.status_code,
            method=res.request.method, reason=res.reason)

    def geturl(self):
        return self._url

    def read(self, amt: int = None):
        try:
            # Interact with urllib3 response directly.
            return self._res.raw.read(amt, decode_content=True)
        # raw is an urllib3 HTTPResponse, so exceptions will be from urllib3
        except urllib3.exceptions.HTTPError as e:
            handle_urllib3_read_exceptions(e)
            raise TransportError(cause=e) from e

    def close(self):
        super().close()
        return self._res.close()

    def tell(self) -> int:
        return self._res.raw.tell()


def handle_urllib3_read_exceptions(e):
    # Sometimes IncompleteRead is wrapped by urllib.exceptions.ProtocolError, so we have to check the args
    ic_read_err = next(
        (err for err in (e, e.__cause__, *(e.args or [])) if isinstance(err, (http.client.IncompleteRead, urllib3.exceptions.IncompleteRead))), None)
    if ic_read_err is not None:
        raise IncompleteRead(partial=ic_read_err.partial, expected=ic_read_err.expected)
    if isinstance(e, urllib3.exceptions.SSLError):
        raise SSLError(cause=e) from e


class YDLRequestsHTTPAdapter(requests.adapters.HTTPAdapter):
    """
    Need to pass our SSLContext and source address to the underlying
    urllib3 PoolManager
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


class RequestsRH(BackendRH):
    SUPPORTED_SCHEMES = ['http', 'https']

    def _initialize(self):
        self.session = YDLRequestsSession()
        _http_adapter = YDLRequestsHTTPAdapter(ydl=self.ydl, ssl_context=self.make_sslcontext())
        self.session.adapters.clear()
        self.session.headers = requests.models.CaseInsensitiveDict({'Connection': 'keep-alive'})
        self.session.mount('https://', _http_adapter)
        self.session.mount('http://', _http_adapter)
        self.session.cookies = self.cookiejar
        # TODO: could use requests hooks for additional logging
        if not self._is_force_disabled:
            if self.print_traffic:
                urllib3.add_stderr_logger()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @property
    def _is_force_disabled(self):
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

    def can_handle(self, request: Request) -> bool:
        if self._is_force_disabled:
            self.write_debug('Not using requests backend as no-requests compat opt is set.', only_once=True)
            return False
        return super().can_handle(request)

    def _real_handle(self, request: Request) -> HTTPResponse:
        # TODO: bring back proxy map
        proxies = {'http': request.proxy, 'https': request.proxy}
        headers = UniqueHTTPHeaderStore(
            make_std_headers(), self.ydl.params.get('http_headers'), request.headers, request.unredirected_headers)
        if 'Accept-Encoding' not in headers:
            headers['Accept-Encoding'] = ', '.join(SUPPORTED_ENCODINGS)

        if not request.compression:
            del headers['accept-encoding']

        max_redirects_exceeded = False
        try:
            res = self.session.request(
                method=request.method,
                url=request.url,
                data=request.data,
                headers=headers,
                timeout=request.timeout,
                proxies=proxies,
                stream=True
            )

        except requests.exceptions.TooManyRedirects as e:
            max_redirects_exceeded = True
            res = e.response
        except requests.exceptions.SSLError as e:
            raise SSLError(cause=e) from e
        except requests.exceptions.ProxyError as e:
            raise ProxyError(cause=e) from e
        except requests.exceptions.ConnectionError as e:
            # TODO: can we process any urllib3 exceptions that may occur here?
            # We could check the args for any relevant errors
            raise TransportError(cause=e) from e
        except urllib3.exceptions.HTTPError as e:
            # Catch any urllib3 exceptions that may leak through
            handle_urllib3_read_exceptions(e)
            raise TransportError(cause=e) from e
        # Any misc Requests exception. May not necessary be network related e.g. InvalidURL
        except requests.exceptions.RequestException as e:
            raise RequestError(cause=e) from e
        requests_res = RequestsResponseAdapter(res)
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
            raise HTTPError(requests_res, redirect_loop=max_redirects_exceeded)  # TODO: redirect loop
        return requests_res

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


# Since we already have a socks proxy implementation,
# we can use that with urllib3 instead of requiring an extra dependency.
class SocksHTTPConnection(urllib3.connection.HTTPConnection):
    def __init__(self, _socks_options, *args, **kwargs):  # must use _socks_options to pass PoolKey checks
        self._proxy_args = _socks_options
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        sock = sockssocket()
        sock.setproxy(**self._proxy_args)
        if type(self.timeout) in (int, float):
            sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))

        # TODO
        except TimeoutError as e:
            raise urllib3.exceptions.ConnectTimeoutError(self, None) from e
        except SocksProxyError as e:
            raise urllib3.exceptions.ProxyError(self, None) from e
        except OSError as e:
            raise urllib3.exceptions.NewConnectionError(self, None) from e

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
        super().__init__(**connection_pool_kw)
        self.pool_classes_by_scheme = {
            'http': SocksHTTPConnectionPool,
            'https': SocksHTTPSConnectionPool
        }


requests.adapters.SOCKSProxyManager = SocksProxyManager
