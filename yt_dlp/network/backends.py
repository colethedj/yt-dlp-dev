import contextlib
import socket
import ssl
import urllib.request
import urllib.error

from .common import (
    HTTPResponse,
    IncompleteRead,
    ReadTimeoutError,
    TransportError,
    ConnectionReset,
    YDLBackendHandler, YDLRequest,
    HTTPError,
    ConnectionTimeoutError, ResolveHostError,
    SSLError
)
import http.client

from ..compat import compat_urllib_request_DataHandler
from ..utils import (
    handle_youtubedl_headers,
    make_HTTPS_handler, YoutubeDLCookieProcessor, PerRequestProxyHandler, YoutubeDLHandler, YoutubeDLRedirectHandler,
)

class HttplibResponseAdapter(HTTPResponse):
    def __init__(self, res: http.client.HTTPResponse):
        self._res = res
        super().__init__(
            headers=res.headers, status=res.status,
            version=res.version if hasattr(res, 'version') else None)

    def geturl(self):
        return self._res.geturl()

    def read(self, amt=None):
        try:
            return self._res.read(amt)
        # TODO: handle exceptions
        except http.client.IncompleteRead as err:
            raise IncompleteRead(err.partial, self.geturl(), cause=err, expected=err.expected) from err
        except ConnectionResetError as err:
            raise ConnectionReset(self.geturl(), cause=err) from err
        except socket.timeout as err:
            raise ReadTimeoutError(self.geturl(), cause=err) from err
        except (OSError, http.client.HTTPException) as err:
            raise TransportError(self.geturl(), cause=err) from err

    def close(self):
        super().close()
        return self._res.close()

    def tell(self) -> int:
        return self._res.tell()


class UrllibHandler(YDLBackendHandler):
    _SUPPORTED_PROTOCOLS = ['http', 'https']

    def _initialize(self):
        cookie_processor = YoutubeDLCookieProcessor(self.cookiejar)
        proxy_handler = PerRequestProxyHandler()
        debuglevel = 1 if self.params.get('debug_printtraffic') else 0
        https_handler = make_HTTPS_handler(self.params, debuglevel=debuglevel)
        ydlh = YoutubeDLHandler(self.params, debuglevel=debuglevel)
        redirect_handler = YoutubeDLRedirectHandler()
        data_handler = compat_urllib_request_DataHandler()

        # TODO: technically the following is not required now, but will keep in for now
        # When passing our own FileHandler instance, build_opener won't add the
        # default FileHandler and allows us to disable the file protocol, which
        # can be used for malicious purposes (see
        # https://github.com/ytdl-org/youtube-dl/issues/8227)
        file_handler = urllib.request.FileHandler()
        def file_open(*args, **kwargs):
            raise urllib.error.URLError('file:// scheme is explicitly disabled in yt-dlp for security reasons')
        file_handler.file_open = file_open
        opener = urllib.request.build_opener(
            proxy_handler, https_handler, cookie_processor, ydlh, redirect_handler, data_handler, file_handler)
        # Delete the default user-agent header, which would otherwise apply in
        # cases where our custom HTTP handler doesn't come into play
        # (See https://github.com/ytdl-org/youtube-dl/issues/1309 for details)
        opener.addheaders = []
        self._opener = opener

    def _real_handle(self, request: YDLRequest, **kwargs) -> HTTPResponse:
        urllib_req = urllib.request.Request(
            url=request.url, data=request.data, headers=dict(request.headers), origin_req_host=request.origin_req_host,
            unverifiable=request.unverifiable, method=request.method
        )

        if not request.compression:
            urllib_req.add_header('Youtubedl-no-compression', True)
        if request.proxy:
            urllib_req.add_header('Ytdl-request-proxy',request.proxy)
        try:
            res = self._opener.open(urllib_req, timeout=request.timeout or self.socket_timeout)

        except urllib.error.HTTPError as e:
            # TODO: create a HTTPResponse from HTTPError
            raise NotImplementedError

        except urllib.error.URLError as e:
            url = e.filename
            # TODO: what errors are raised outside URLError?
            try:
                raise e.reason from e
            except TimeoutError as e:
                raise ConnectionTimeoutError(url=url, cause=e) from e
            except socket.gaierror as e:
                raise ResolveHostError(url=url, cause=e) from e
            except ssl.SSLError as e:
                raise SSLError(url=url, cause=e) from e
            except:
                raise TransportError(url=url, cause=e) from e

        except http.client.HTTPException as e:
            raise TransportError(cause=e) from e
        return HttplibResponseAdapter(res)
