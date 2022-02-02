import abc
import bisect
import http.cookiejar
import http.client
import io
import urllib.parse
from collections import OrderedDict
from typing import List
from urllib.error import HTTPError
from abc import ABC, abstractmethod
from http import HTTPStatus
from email.message import Message

Request: urllib.request.Request


# TODO: add support for unified debug printing?
# TODO: This and the subclasses will likely need some work
class BaseHTTPResponse(ABC, io.IOBase):
    """
    Adapter interface for responses
    """

    REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308]

    def __init__(self, headers, status, version, reason):
        self.headers = YDLHTTPHeaderStore(headers)
        self.status = self.code = status
        self.reason = reason
        if not reason:
            try:
                self.reason = HTTPStatus(status).value
            except ValueError:
                pass
        self.version = version  # HTTP Version, e.g. HTTP 1.1 = 11

    def getcode(self):
        return self.status

    @property
    def url(self):
        return self.geturl()

    @abstractmethod
    def geturl(self):
        """return the final url"""
        pass

    def get_redirect_url(self):
        return self.getheader('location') if self.status in self.REDIRECT_STATUS_CODES else None

    def getheaders(self):
        return self.headers

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def info(self):
        return self.headers

    def readable(self):
        return True

    @abstractmethod
    def read(self, amt: int = None):
        raise NotImplementedError


class BackendHandler:

    def __init__(self, youtubedl_params: dict, ydl_logger, cookies):
        self._next_handler = None
        self.params = youtubedl_params
        self.logger = ydl_logger
        self.cookies = cookies
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
    def can_handle(cls, request: Request, **req_kwargs) -> bool:
        """Validate if handler is suitable for given request. Redefine in subclasses."""

    def _real_handle(self, request: Request, proxies=None) -> BaseHTTPResponse:
        """Real request handling process. Redefine in subclasses"""
        pass


class HTTPBackendHandler(BackendHandler):

    _SUPPORTED_PROTOCOLS: list

    @classmethod
    def _is_supported_protocol(cls, request: Request):
        return urllib.parse.urlparse(request.full_url).scheme.lower() in cls._SUPPORTED_PROTOCOLS

    @classmethod
    def can_handle(cls, request: Request, **req_kwargs) -> bool:
        return cls._is_supported_protocol(request)


class UnsupportedBackendHandler(BackendHandler):
    def can_handle(self, request: Request, **req_kwargs):
        raise Exception('This request is not supported')


class Session:

    def __init__(self, youtubedl_params: dict, logger):
        self._first_handler = None
        self._last_handler = None
        self._logger = logger
        self.params = youtubedl_params

    def add_handler(self, handler: BackendHandler):
        if self._first_handler is None:
            self._first_handler = self._last_handler = handler
        else:
            self._last_handler = self._last_handler.set_next(handler)

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

    def send_request(self, request: urllib.request.Request):
        return self._first_handler.handle(request, proxies=self._make_proxy_map(request))


class YDLHTTPHeaderStore(Message):
    def __init__(self, data=None):
        super().__init__()
        if data is not None:
            self.add_headers(data)

    def add_headers(self, data):
        for k, v in data.items():
            self.add_header(k, v)

    def replace_headers(self, data):
        for k, v in data.items():
            self.replace_header(k, v)

    def copy(self):
        return YDLHTTPHeaderStore(self)


# goes in YoutubeDL class?
def create_session(youtubedl_params, ydl_logger):
    adapters = [UnsupportedBackendHandler]
    session = Session(youtubedl_params, logger=ydl_logger)
    cookiejar = http.cookiejar.CookieJar()
    for adapter in adapters:
        if not adapter:
            continue
        session.add_handler(adapter(youtubedl_params, None, cookiejar))


"""
BackendError
    RequestError
        HTTPError (similar to urllib.error.HTTPError)
        
        TimeoutError
            ReadTimeoutError (also inherits NetworkError)
            ConnectionTimeoutError (also inherits NetworkError)
        
        NetworkError # TODO
            # making req
            ResolveHostnameError (host name resolution error, DNS Error)
            
            # during req/response
            IncompleteReadError
            # Covers HTTPExceptions: connection reset, incomplete read, remote disconnected, etc.
        
        SSLError
            CertificateError (for help text)
            ... ?
        ProxyError
            Socks proxy error, etc.
        
        ContentDecodingError
        MaxRedirectsError
        

Other notes:
- add original request obj to every RequestError
- each BackendError will have backend details 
"""

"""


  
        #TransportError / Connection error / Network error (?). Prob most of our socket errors here
       #  ProtocolError - errors during request/response (?)
            # todo:
            # HTTPException like Errors - related to reading the response
            #    ConnectionResetError
            #    RemoteDisconnected
            #    Incomplete read
            #    ...
            
                

    

"""