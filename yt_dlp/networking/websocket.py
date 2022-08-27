from .common import Response, Request, RequestHandler
from .exceptions import TransportError


class WebSocketResponse(Response):

    def send(self, *args):
        raise NotImplementedError

    def recv(self, *args):
        raise NotImplementedError

    def close(self, status=None):
        super().close()
        raise NotImplementedError


class WebSocketRequest(Request):

    @classmethod
    def from_request(cls, request):
        if not isinstance(request, Request):
            raise TypeError('request must be a Request')
        return cls(
            url=request.url,
            data=request.data,
            headers=request.headers.copy(),
            method=request.method,
            compression=request.compression,
            proxies=request.proxies.copy(),
            timeout=request.timeout,
            allow_redirects=request.allow_redirects
        )


class WebSocketException(TransportError):
    pass


class WebSocketRequestHandler(RequestHandler):

    def _prepare_request(self, request: Request):
        return self._prepare_websocket_request(WebSocketRequest.from_request(request))

    def _prepare_websocket_request(self, request: WebSocketRequest):
        return request

    def _real_handle(self, request: WebSocketRequest):
        raise NotImplementedError
