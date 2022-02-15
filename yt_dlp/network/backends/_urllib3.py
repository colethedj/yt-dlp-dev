import errno
import re

from ...compat import (
    compat_http_client,
    compat_brotli,
    compat_urllib3, compat_urllib_parse_urlparse, compat_urllib_parse
)
from ...exceptions import (
    IncompleteRead,
    ConnectionReset,
    ReadTimeoutError,
    TransportError,
    ConnectionTimeoutError,
    ResolveHostError,
    SSLError,
    bug_reports_message,
    HTTPError,
    ProxyError, RequestError
)
from ..common import HTTPResponse, YDLBackendHandler, YDLRequest, get_std_headers
from ..socksproxy import ProxyType, sockssocket
from ..utils import (
    make_ssl_context
)

if not compat_urllib3:
    has_urllib3 = False
else:
    has_urllib3 = True

URLLIB3_SUPPORTED_ENCODINGS = [
    'gzip', 'deflate'
]
if compat_brotli:
    URLLIB3_SUPPORTED_ENCODINGS.append('br')


class Urllib3ResponseAdapter(HTTPResponse):
    def __init__(self, res):
        self._res = res
        self._url = res.geturl()
        if self._url:
            url_parsed = compat_urllib_parse_urlparse(self._url)
            if isinstance(url_parsed, compat_urllib_parse.ParseResultBytes):
                url_parsed = url_parsed.decode()
            if url_parsed.hostname is None:
                # hack
                netloc = f'{res.connection.host}:{res.connection.port}'
                url_parsed = url_parsed._replace(
                    netloc=netloc,
                    scheme='https')
            self._url = url_parsed.geturl()

        super().__init__(
            headers=res.headers, status=res.status,
            version=res.version)

    def geturl(self):
        return self._url

    def read(self, amt: int = None):
        try:
            return self._res.read(amt)
        except compat_urllib3.exceptions.IncompleteRead as e:
            raise IncompleteRead(e.partial, self.geturl(), cause=e, expected=e.expected) from e
        except compat_urllib3.exceptions.SSLError as e:
            raise SSLError(self.geturl(), cause=e) from e
        except compat_urllib3.exceptions.ReadTimeoutError as e:
            raise ReadTimeoutError(self.geturl(), cause=e) from e
        except compat_urllib3.exceptions.ProtocolError as e:
            original_cause = e.__cause__
            if isinstance(original_cause, compat_http_client.IncompleteRead) or 'incomplete read' in str(e).lower():
                if original_cause:
                    partial, expected = original_cause.partial, original_cause.expected
                else:
                    # TODO: capture incomplete read detail with regex
                    raise NotImplementedError

                raise IncompleteRead(partial, self.geturl(), cause=e, expected=expected) from e
            elif isinstance(original_cause, ConnectionResetError) or 'connection reset' in str(e).lower():
                raise ConnectionReset(self.geturl(), e, cause=e) from e
            elif isinstance(original_cause, OSError):
                if original_cause.errno == errno.ECONNRESET:
                    raise ConnectionReset(self.geturl(), cause=e) from e
                if original_cause.errno == errno.ETIMEDOUT:
                    raise ReadTimeoutError(self.geturl(), cause=e) from e

            raise TransportError(self.geturl(), e, cause=e) from e

    def close(self):
        super().close()
        return self._res.close()

    def tell(self) -> int:
        return self._res.tell()


class Urllib3Handler(YDLBackendHandler):
    _SUPPORTED_PROTOCOLS = ['http', 'https']

    def _initialize(self):
        self.pools = {}
        if not self._is_force_disabled:
            if self.print_traffic:
                compat_urllib3.add_stderr_logger()
        compat_urllib3.disable_warnings()

    @property
    def _is_force_disabled(self):
        if 'no-urllib3' in self.ydl.params.get('compat_opts', []):
            return True
        return False

    def _create_pm(self, proxy=None):
        pm_args = {'ssl_context': make_ssl_context(self.ydl.params)}
        source_address = self.ydl.params.get('source_address')
        if source_address:
            pm_args['source_address'] = (source_address, 0)

        if proxy:
            proxy = self.unified_proxy_url(proxy)
            if proxy.startswith('socks'):
                # TODO: implement custom SOCKSProxyManager
                raise NotImplementedError
            else:
                pm = compat_urllib3.ProxyManager(
                    proxy_url=proxy, proxy_ssl_context=pm_args.get('ssl_context'), **pm_args)
        else:
            pm = compat_urllib3.PoolManager(**pm_args)
        return pm

    def get_pool(self, proxy=None):
        return self.pools.setdefault(proxy or '__noproxy__', self._create_pm(proxy))

    def _can_handle(self, request: YDLRequest, **req_kwargs) -> bool:
        if isinstance(request.proxy, str) and request.proxy.startswith('socks'):
            self.report_warning('SOCKS proxy is not yet supported by urllib3 handler.', only_once=True)
            return False
        if self._is_force_disabled:
            self.write_debug('Not using urllib3 backend as no-urllib3 compat opt is set.', only_once=True)
            return False
        return super()._can_handle(request, **req_kwargs)

    def _real_handle(self, request: YDLRequest, **kwargs) -> HTTPResponse:
        self.cookiejar.add_cookie_header(request)

        # TODO: implement custom redirect mixin for unified redirect handling
        # Remove headers not meant to be forwarded to different host
        retries = compat_urllib3.Retry(
            remove_headers_on_redirect=request.unredirected_headers.keys(),
            raise_on_redirect=False, other=0, read=0, connect=0)
        all_headers = get_std_headers(URLLIB3_SUPPORTED_ENCODINGS)
        all_headers.replace_headers(request.headers)
        all_headers.replace_headers(request.unredirected_headers)
        if not request.compression:
            del all_headers['accept-encoding']
        try:
            try:
                urllib3_res = self.get_pool(request.proxy).urlopen(
                    method=request.method,
                    url=request.url,
                    request_url=request.url,  # TODO: needed for redirect compat
                    headers=dict(all_headers),
                    body=request.data,
                    preload_content=False,
                    timeout=request.timeout,
                    retries=retries,
                    redirect=True
                )

            except compat_urllib3.exceptions.MaxRetryError as r:
                raise r.reason

        # TODO: these all need A LOT of work
        # TODO: this is recent
        # except compat_urllib3.exceptions.NameResolutionError as e:
        #     # TODO: better regex
        #     mobj = re.match(r"Failed to resolve '(?P<host>[^']+)' \((?P<reason>[^)]*)", str(e))
        #     raise ResolveHostError(host=mobj.group('host'), cause=e) from e

        except compat_urllib3.exceptions.ReadTimeoutError as e:
            raise ReadTimeoutError(e.url, msg=str(e), cause=e) from e
        except compat_urllib3.exceptions.ConnectTimeoutError as e:
            raise ConnectionTimeoutError(msg=str(e), cause=e) from e
        except compat_urllib3.exceptions.SSLError as e:
            raise SSLError(cause=e, msg=str(e)) from e

        except compat_urllib3.exceptions.IncompleteRead as e:
            raise IncompleteRead(partial=e.partial, expected=e.expected, cause=e) from e

        except compat_urllib3.exceptions.ProxyError as e:
            raise ProxyError(msg=str(e), cause=e) from e  # will likely need to handle this differently
        except compat_urllib3.exceptions.ProtocolError as e:
            raise TransportError(msg=str(e), cause=e) from e

        except compat_urllib3.exceptions.RequestError as e:
            raise RequestError(msg=str(e), url=e.url) from e

        except compat_urllib3.exceptions.HTTPError as e:
            raise RequestError(msg=str(e)) from e

        res = Urllib3ResponseAdapter(urllib3_res)
        if not (
                (200 <= res.status < 300)
                or (res.status in (301, 302, 303, 307, 308) and request.get_method() in ('GET', 'HEAD'))
                or (res.status in (301, 302, 303) and request.get_method() == 'POST')
        ):
            raise HTTPError(res, res.url)

        if self.cookiejar:
            self.cookiejar.extract_cookies(res, request)

        return res