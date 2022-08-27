from __future__ import annotations

import asyncio
import atexit
import logging
import sys

from .common import Response
from .exceptions import UnsupportedRequest
from .websocket import WebSocketResponse, WebSocketRequestHandler
from ..dependencies import websockets


class WebsocketsResponseAdapter(WebSocketResponse):

    def __init__(self, wsw: WebSocketsWrapper, url):
        super().__init__(wsw, url=url, headers=wsw.conn.protocol.response_headers, status=101)

    def read(self, amt: int = None):
        # TODO: get access to original response data
        return b''

    def close(self, status=None):
        self.raw.__exit__(None, None, None)
        super(Response).close()

    def tell(self) -> int:
        return 0

    def send(self, *args):
        return self.raw.send(*args)

    def recv(self, *args):
        return self.raw.recv(*args)


class WebsocketsRH(WebSocketRequestHandler):
    SUPPORTED_SCHEMES = ['wss', 'ws']
    SUPPORTED_PROXY_SCHEMES = []
    NAME = 'aaugustin.websockets'

    def __init__(self, ydl):

        super().__init__(ydl)
        if self.ydl.params.get('debug_printtraffic') and websockets:
            for l in ('websockets.client', 'websockets.server'):
                logger = logging.getLogger(l)
                logger.setLevel('DEBUG')
                handler = logging.StreamHandler(stream=sys.stdout)
                handler.setFormatter(logging.Formatter(f'[{self.NAME}] {l}: %(message)s'))
                logger.addHandler(handler)
                logger.setLevel(logging.DEBUG)

    def _prepare_websocket_request(self, request):
        if not websockets:
            raise UnsupportedRequest('websockets is not installed')
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
        response = WebsocketsResponseAdapter(wrapper, url=request.url)
        return response


class WebSocketsWrapper:
    """Wraps websockets module to use in non-async scopes"""
    pool = None

    def __init__(self, url, headers=None, connect=True, **ws_kwargs):
        self.loop = asyncio.new_event_loop()
        # XXX: "loop" is deprecated
        self.conn = websockets.connect(
            url, extra_headers=headers, ping_interval=None,
            close_timeout=float('inf'), loop=self.loop, ping_timeout=float('inf'), **ws_kwargs)
        if connect:
            self.__enter__()
        atexit.register(self.__exit__, None, None, None)

    def __enter__(self):
        if not self.pool:
            self.pool = self.run_with_loop(self.conn.__aenter__(), self.loop)
        return self

    def send(self, *args):
        self.run_with_loop(self.pool.send(*args), self.loop)

    def recv(self, *args):
        return self.run_with_loop(self.pool.recv(*args), self.loop)

    def __exit__(self, type, value, traceback):
        try:
            return self.run_with_loop(self.conn.__aexit__(type, value, traceback), self.loop)
        finally:
            self.loop.close()
            self._cancel_all_tasks(self.loop)

    # taken from https://github.com/python/cpython/blob/3.9/Lib/asyncio/runners.py with modifications
    # for contributors: If there's any new library using asyncio needs to be run in non-async, move these function out of this class
    @staticmethod
    def run_with_loop(main, loop):
        if not asyncio.iscoroutine(main):
            raise ValueError(f'a coroutine was expected, got {main!r}')

        try:
            return loop.run_until_complete(main)
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            if hasattr(loop, 'shutdown_default_executor'):
                loop.run_until_complete(loop.shutdown_default_executor())

    @staticmethod
    def _cancel_all_tasks(loop):
        to_cancel = asyncio.all_tasks(loop)

        if not to_cancel:
            return

        for task in to_cancel:
            task.cancel()

        # XXX: "loop" is removed in python 3.10+
        loop.run_until_complete(
            asyncio.gather(*to_cancel, loop=loop, return_exceptions=True))

        for task in to_cancel:
            if task.cancelled():
                continue
            if task.exception() is not None:
                loop.call_exception_handler({
                    'message': 'unhandled exception during asyncio.run() shutdown',
                    'exception': task.exception(),
                    'task': task,
                })
