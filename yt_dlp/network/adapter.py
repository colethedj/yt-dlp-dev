import abc
import bisect
import http.cookiejar
from http.client import HTTPResponse
import urllib.request
import urllib.parse
from collections import OrderedDict
from typing import List

Request: urllib.request.Request


class BaseBackendHandler:

    _SUPPORTED_PROTOCOLS: list

    def __init__(self, youtubedl_params: dict, ydl_logger):
        self._next_handler = None
        self.params = youtubedl_params
        self.logger = ydl_logger
        self._initialize()

    def _initialize(self):
        """Initialization process. Redefine in subclasses."""
        pass

    def set_next(self, handler):
        self._next_handler = handler
        return handler

    def handle(self, request: Request, **req_kwargs):
        if self.can_handle(request, **req_kwargs):
            res = self._real_handle(request, **req_kwargs)
            if res:
                return res
        if self._next_handler:
            return self._next_handler.handle(request, **req_kwargs)

    @classmethod
    def _is_supported_protocol(cls, request: Request):
        return urllib.parse.urlparse(request.full_url).scheme.lower() in cls._SUPPORTED_PROTOCOLS

    @classmethod
    def can_handle(cls, request: Request, **req_kwargs) -> bool:
        return cls._is_supported_protocol(request)

    def _real_handle(self, request: Request, proxies=None) -> HTTPResponse:
        """Real request handling process. Redefine in subclasses"""
        pass


class UnsupportedBackendHandler(BaseBackendHandler):
    def can_handle(self, request: Request, **req_kwargs):
        raise Exception('This request is not supported')


class MyBackendHandler(BaseBackendHandler):
    _SUPPORTED_PROTOCOLS = ['http', 'https']

    def can_handle(self, request: Request, **req_kwargs) -> bool:
        if req_kwargs.get('proxies'):
            return False
        return super().can_handle(request, **req_kwargs)


class Session:

    def __init__(self, youtubedl_params: dict, logger):
        self._handler_chain = None
        self._logger = logger
        self.params = youtubedl_params
        self.cookiejar = http.cookiejar.CookieJar()

    def add_handler(self, handler: BaseBackendHandler):
        if self._handler_chain is None:
            self._handler_chain = handler
        else:
            self._handler_chain = self._handler_chain.set_next(handler)

    def _make_proxy_map(self, request: Request = None):
        proxy = None
        if request is not None:
            req_proxy = request.headers.get('Ytdl-request-proxy')
            if req_proxy is not None:
                proxy = req_proxy
                del request.headers['Ytdl-request-proxy']

        opts_proxy = self.params.get('proxy')
        if not proxy and opts_proxy:
            proxy = opts_proxy

        if proxy:
            return {'http': opts_proxy, 'https': opts_proxy}

        proxies = urllib.request.getproxies()
        # Set HTTPS proxy to HTTP one if given (https://github.com/ytdl-org/youtube-dl/issues/805)
        if 'http' in proxies and 'https' not in proxies:
            proxies['https'] = proxies['http']
        return proxies

    def urlopen(self, request: urllib.request.Request):
        self.cookiejar.add_cookie_header(request)
        res = self._handler_chain.handle(request, proxies=self._make_proxy_map(request))
        if res:
            self.cookiejar.extract_cookies(res, request)
        return res


# goes in YoutubeDL class?
def create_session(youtubedl_params, ydl_logger):
    adapters = [UnsupportedBackendHandler, MyBackendHandler]
    session = Session(youtubedl_params, logger=ydl_logger)
    for adapter in adapters:
        if not adapter:
            continue
        session.add_handler(adapter(youtubedl_params, None))
