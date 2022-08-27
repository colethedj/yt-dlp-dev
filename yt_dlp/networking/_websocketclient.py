from .exceptions import UnsupportedRequest
from .websocket import WebSocketResponse, WebSocketRequestHandler

from ..dependencies import websocket as websocket_client


class WebsocketClientResponseAdapter(WebSocketResponse):

    def __init__(self, ws, url):
        super().__init__(ws, url=url, headers=ws.headers, status=ws.status)

    def read(self, amt: int = None):
        return b''

    def send(self, *args):
        return self.raw.send(*args)

    def recv(self, *args):
        return self.raw.recv(*args)

    def close(self, status=None):
        self.raw.close()
        super().close()


class WebsocketClientRH(WebSocketRequestHandler):
    SUPPORTED_SCHEMES = ['wss', 'ws']
    SUPPORTED_PROXY_SCHEMES = []
    NAME = 'websocket-client'

    def __init__(self, ydl):
        super().__init__(ydl)
        if self.ydl.params.get('debug_printtraffic') and websocket_client:
            websocket_client.enableTrace(True)

    def _prepare_websocket_request(self, request):
        if not websocket_client:
            raise UnsupportedRequest('websocket-client is not installed')

        if self.ydl.params.get('source_address'):
            raise UnsupportedRequest('source_address is not supported')
        return request  # TODO: add an assert check in main

    def _real_handle(self, request):
        ws = websocket_client.WebSocket()
        ws.connect(
            request.url,
            origin=request.headers.pop('Origin', None),
            host=request.headers.pop('Host', None),
            sslopt={'context': self.make_sslcontext()},
            timeout=request.timeout
        )

        return WebsocketClientResponseAdapter(ws, url=request.url)


