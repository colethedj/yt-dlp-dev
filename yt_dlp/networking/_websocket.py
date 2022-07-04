import logging
import sys

from . import UrllibRH
from .common import Response

from ..utils import WebSocketsWrapper
from .exceptions import UnsupportedRequest


class WebSocketsResponse(Response):

    def __init__(self, wsw: WebSocketsWrapper, url):
        # TODO: raw should be the original http response, if possible
        super().__init__(wsw, url=url, headers=wsw.conn.protocol.response_headers, status=101)

    def read(self, amt: int = None):
        # TODO: get access to original response data
        return b''

    def close(self):
        self.raw.__exit__(None, None, None)
        super(Response).close()

    def tell(self) -> int:
        return 0

    def send(self, *args):
        return self.raw.send(*args)

    def recv(self, *args):
        return self.raw.recv(*args)


# FIXME: don't use urllibRH
class WebSocketsRequestHandler(UrllibRH):
    SUPPORTED_SCHEMES = ['wss', 'ws']
    NAME = 'websockets'

    def __init__(self, ydl):

        super().__init__(ydl)
        if self.ydl.params.get('debug_printtraffic'):
            for l in ('websockets.client', 'websockets.server'):
                logger = logging.getLogger(l)
                logger.setLevel('DEBUG')
                handler = logging.StreamHandler(stream=sys.stdout)
                handler.setFormatter(logging.Formatter(f'{l}: %(message)s'))
                logger.addHandler(handler)
                logger.setLevel(logging.DEBUG)

    def _prepare_request(self, request):
        if request.proxies:
            raise UnsupportedRequest('proxy support is not implemented')
        return request

    def _real_handle(self, request):
        ws_kwargs = {
            'ssl': self.make_sslcontext()
        }
        source_address = self.ydl.params.get('source_address')
        if source_address is not None:
            ws_kwargs['source_address'] = source_address
        wrapper = WebSocketsWrapper(
            request.url, headers=request.headers, connect=True, **ws_kwargs)
        wrapper.loop.set_debug(True)
        response = WebSocketsResponse(wrapper, url=request.url)

        return response
