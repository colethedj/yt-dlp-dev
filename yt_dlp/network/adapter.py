import abc
import bisect
import http.cookiejar

import urllib.request
import urllib.parse
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import List


class NotSuitableError(Exception):
    ...


class BaseBackendAdapter(ABC):

    BACKEND_NAME: str
    PRIORITY = 0  # highest priority
    PROTOCOLS: list

    def __init__(self, cookies: http.cookiejar.CookieJar, youtubedl_params: dict):
        self.cookiejar = cookies
        self.params = youtubedl_params
        super(BaseBackendAdapter).__init__()

    def request(self, request: urllib.request.Request, *req_args, **req_kwargs):
        scheme = urllib.parse.urlparse(request.full_url).scheme  # do we want this here?
        if scheme.lower() not in self.PROTOCOLS:
            raise NotSuitableError(f'{scheme} is not a supported scheme')
        return self._request(request, *req_args, **req_kwargs)

    @abstractmethod
    def _request(self, request: urllib.request.Request, proxies=None):
        raise NotImplementedError('This function must be implemented by subclasses')

    def __lt__(self, other):
        return self.PRIORITY < other.PRIORITY


class MyBackendAdapter(BaseBackendAdapter):
    BACKEND_NAME = 'my backend'
    PRIORITY = 40
    PROTOCOLS = ['http', 'https']

    def __init__(self, cookies: http.cookiejar.CookieJar, youtubedl_params: dict):
        super().__init__(cookies, youtubedl_params)
        # do some stuff

    def _request(self, request: urllib.request.Request, proxies=None):
        if proxies:
            raise NotSuitableError
        raise NotImplementedError


class Session:

    def __init__(self, youtubedl_params: dict, logger, proxies=None):
        self._adapters: List[BaseBackendAdapter] = []
        self.global_proxies = proxies or {}
        self._logger = logger
        self.params = youtubedl_params

    def add_adapter(self, adapter):
        bisect.insort_left(self._adapters, adapter)

    def remove_adapter(self, adapter: BaseBackendAdapter):
        self._adapters.remove(adapter)

    def send(self, request: urllib.request.Request):
        last_err = None
        for adapter in self._adapters:
            try:
                return adapter.request(request, proxies=self.global_proxies)
            except NotSuitableError as e:
                last_err = e
                self._logger.debug(f'{adapter.BACKEND_NAME} backend could not be used: {e}')
        raise Exception('No appropriate adapter available that can resolve this request. ' + str(last_err) if last_err else '')


# goes in YoutubeDL class?
def create_session(youtubedl_params, ydl_logger):
    adapters = [MyBackendAdapter]
    session = Session(youtubedl_params, logger=ydl_logger)
    cookies = http.cookiejar.CookieJar()
    for adapter in adapters:
        if not adapter:
            continue
        session.add_adapter(adapter(cookies, youtubedl_params))
