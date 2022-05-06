import errno

from requests.cookies import merge_cookies

from ..compat import (
    compat_http_client,
    compat_urllib_parse_urlparse,
    compat_urllib_parse,
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
    make_ssl_context,
    socks_create_proxy_args
)

from ..utils import (
    IncompleteRead,
    ReadTimeoutError,
    TransportError,
    SSLError,
    HTTPError,
    ProxyError, ConnectTimeoutError, urljoin
)

import requests.adapters

import requests
from urllib3.util.url import parse_url
import urllib3.connection

SUPPORTED_ENCODINGS = [
    'gzip', 'deflate'
]

# TODO: fix this for requests
# TODO: make it a requirement to have urllib3 >= 1.26.9
# urllib3 does not support brotlicffi on versions < 1.26.9
if compat_brotli and not (compat_brotli.__name__ == 'brotlicffi' and urllib3.__version__ < '1.26.9'):
    SUPPORTED_ENCODINGS.append('br')


# TODO: implement this for requests
class _Urllib3HTTPError(HTTPError):
    """
    INTERNAL USE ONLY, catch utils.HTTPError instead.

    Close the connection instead of releasing it to the pool.
    May help with recovering from temporary errors related to persistent connections (e.g. temp block)
    """
    def __init__(self, response, *args, **kwargs):
        def release_conn_override():
            if response._res._connection:
                response._res._connection.close()
                response._res._connection = None
        response._res.release_conn = release_conn_override
        super().__init__(response, *args, **kwargs)


class RequestsResponseAdapter(HTTPResponse):
    def __init__(self, res):
        self._res = res
        self._url = res.url

        super().__init__(
            headers=res.headers, status=res.status_code)

    def geturl(self):
        return self._url

    def read(self, amt: int = None):
        try:
            # Interact with urllib3 response directly.
            return self._res.raw.read(amt, decode_content=True)
        # raw is an urllib3 HTTPResponse, so exceptions will be from urllib3
        except urllib3.exceptions.ReadTimeoutError as e:
            raise ReadTimeoutError(cause=e) from e
        except urllib3.exceptions.IncompleteRead as e:
            raise IncompleteRead(partial=e.partial, expected=e.expected, cause=e) from e
        except urllib3.exceptions.SSLError as e:
            # TODO: can we get access to the underlying SSL reason?
            original_cause = e.__cause__
            raise SSLError(cause=e, msg=str(original_cause.args if original_cause else str(e))) from e

    def close(self):
        super().close()
        return self._res.close()

    def tell(self) -> int:
        return self._res.raw.tell()


class YDLRequestsHTTPAdapter(requests.adapters.HTTPAdapter):

    def __init__(self, ydl, *args, **kwargs):
        self.ydl = ydl
        self._pm_args = {
            'ssl_context': make_ssl_context(self.ydl.params),
        }
        source_address = self.ydl.params.get('source_address')
        if source_address:
            self._pm_args['source_address'] = (source_address, 0)
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=..., **pool_kwargs):
        pool_kwargs.update(self._pm_args)
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs.update(self._pm_args)
        super().proxy_manager_for(proxy, **proxy_kwargs)


class RequestsRH(BackendRH):
    SUPPORTED_SCHEMES = ['http', 'https']

    def _initialize(self):
        self.session = requests.session()
        _http_adapter = YDLRequestsHTTPAdapter(ydl=self.ydl)
        self.session.mount('https', _http_adapter)
        self.session.mount('http', _http_adapter)
        # TODO
        if not self._is_force_disabled:
            if self.print_traffic:
                urllib3.add_stderr_logger()
        urllib3.disable_warnings()

    @property
    def _is_force_disabled(self):
        if 'no-requests' in self.ydl.params.get('compat_opts', []):
            return True
        return False

    def can_handle(self, request: Request) -> bool:
        if self._is_force_disabled:
            self.write_debug('Not using requests backend as no-requests compat opt is set.', only_once=True)
            return False
        return super().can_handle(request)

    def _real_handle(self, request: Request) -> HTTPResponse:
        # TODO: no-compression handling
        proxies = {'http': request.proxy, 'https': request.proxy}
        try:
            res = self.session.request(
                method=request.method,
                url=request.url,
                data=request.data,
                headers=UniqueHTTPHeaderStore(request.headers, request.unredirected_headers),
                timeout=request.timeout,
                proxies=proxies,
                cookies=self.cookiejar,
                verify=False,  # We use SSLContext for this which is set in the PoolManager
                stream=True
            )
            # TODO: rest of handling
        finally:
            self.session.cookies.clear()
        merge_cookies(self.cookiejar, res.cookies)  # TODO: cookies won't get updated if something fails mid-redirect
        return RequestsResponseAdapter(res)


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
            raise urllib3.exceptions.ConnectTimeoutError from e
        except SocksProxyError as e:
            raise urllib3.exceptions.ProxyError from e
        except OSError as e:
            raise urllib3.exceptions.NewConnectionError from e

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
