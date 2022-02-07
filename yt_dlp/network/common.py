import abc
import bisect
import http.cookiejar
import http.client
import io
import sys
import urllib.parse
from collections import OrderedDict
from typing import List
from urllib.error import HTTPError
from abc import ABC, abstractmethod
from http import HTTPStatus
from email.message import Message
import urllib.request
import tempfile
import urllib.response
from ..utils import YoutubeDLError
from yt_dlp.utils import extract_basic_auth, escape_url, sanitize_url


class YDLRequest:
    """
    Our own request class, similar to urllib.request.Request
    This is used to send request information from youtube-dl to the backends.
    Backends are expected to extract relevant data from this object rather that use it directly (e.g. passing to urllib)
    """
    def __init__(
            self, url, data=None, headers=None, proxy=None, compression=True, method=None,
            unverifiable=False, unredirected_headers=None, origin_req_host=None):
        """
        @param proxy: proxy to use for the request, e.g. socks5://127.0.0.1:1080. Default is None.
        @param compression: whether to include content-encoding header on request (i.e. disable/enable compression).
        For everything else, see urllib.request.Request docs: https://docs.python.org/3/library/urllib.request.html?highlight=request#urllib.request.Request

        Headers are stored internally in a YDLHTTPHeaderStore. Be careful not to have multiple headers (TODO: do we want to add something to prevent this?)
        """
        url, basic_auth_header = extract_basic_auth(escape_url(sanitize_url(url)))
        # Using Request object for url parsing.
        self.__request_url_store = urllib.request.Request(url)
        self._method = method
        self._data = data
        self._headers = YDLUniqueHTTPHeaderStore(headers)
        self._unredirected_headers = YDLUniqueHTTPHeaderStore(unredirected_headers)

        # TODO: add support for passing different types of auth into a YDlRequest, and don't add the headers.
        #  That can be done in the backend
        if basic_auth_header:
            self.unredirected_headers['Authorization'] = basic_auth_header

        self.proxy = proxy
        self.compression = compression

        # See https://docs.python.org/3/library/urllib.request.html#urllib.request.Request
        # and https://datatracker.ietf.org/doc/html/rfc2965.html
        self.unverifiable = unverifiable
        self.origin_req_host = (
                origin_req_host
                or urllib.parse.urlparse(self.url).netloc
                or self.__request_url_store.origin_req_host)

    @property
    def url(self):
        return self.__request_url_store.full_url

    @property
    def data(self):
        return self._data

    @property
    def headers(self):
        return self._headers

    @property
    def unredirected_headers(self):
        """Headers to not send in a redirect"""
        return self._unredirected_headers

    @property
    def method(self):
        return self._method or 'POST' if self._data else 'GET'

    def copy(self):
        return self.__class__(
            self.url, self.data, self.headers.copy(), self.proxy, self.compression, self.method, self.unverifiable,
            self.unredirected_headers.copy())

    # Backwards compatible functions with urllib.request.Request for cookiejar handling

    def add_unredirected_header(self, key, value):
        self._unredirected_headers.replace_header(key, value)

    def add_header(self, key, value):
        self._headers.replace_header(key, value)

    def has_header(self, header):
        return header in self._headers or header in self._unredirected_headers

    def remove_header(self, key):
        del self._headers[key]
        del self._unredirected_headers[key]

    def get_header(self, key, default=None):
        return self._headers.get(key, self._unredirected_headers.get(key, default))

    def header_items(self):
        return list({**self._unredirected_headers, **self._headers}.items())

    def get_full_url(self):
        return self.url

    def get_method(self):
        return self.method


class HEADRequest(YDLRequest):
    @property
    def method(self):
        return 'HEAD'


class PUTRequest(YDLRequest):
    @property
    def method(self):
        return 'PUT'


# TODO: add support for unified debug printing?
# TODO: This and the subclasses will likely need some work
# TODO: add original request (or request history?)
class HTTPResponse(ABC, io.IOBase):
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


class BaseBackendHandler:

    _next_handler = None

    def handle(self, request: YDLRequest, **req_kwargs):
        if self.can_handle(request, **req_kwargs):
            res = self._real_handle(request, **req_kwargs)
            if res:
                return res
        if self._next_handler:
            return self._next_handler.handle(request, **req_kwargs)

    @classmethod
    def can_handle(cls, request: YDLRequest, **req_kwargs) -> bool:
        """Validate if handler is suitable for given request. Can override in subclasses."""

    def _real_handle(self, request: YDLRequest, **kwargs) -> HTTPResponse:
        """Real request handling process. Redefine in subclasses"""


class YDLBackendHandler(BaseBackendHandler):

    _SUPPORTED_PROTOCOLS: list

    def __init__(self, youtubedl_params: dict, ydl_logger, cookies):
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

    def handle(self, request: YDLRequest, **req_kwargs):
        if self.can_handle(request, **req_kwargs):
            res = self._real_handle(request, **req_kwargs)
            if res:
                return res
        if self._next_handler:
            return self._next_handler.handle(request, **req_kwargs)

    @classmethod
    def _is_supported_protocol(cls, request: YDLRequest):
        return urllib.parse.urlparse(request.url).scheme.lower() in cls._SUPPORTED_PROTOCOLS

    @classmethod
    def can_handle(cls, request: YDLRequest, **req_kwargs) -> bool:
        """Validate if handler is suitable for given request. Can override in subclasses."""
        return cls._is_supported_protocol(request)


class UnsupportedBackendHandler(BaseBackendHandler):
    def can_handle(self, request: YDLRequest, **req_kwargs):
        raise Exception('This request is not supported')


class Session:

    def __init__(self, youtubedl_params: dict, logger):
        self._first_handler = None
        self._last_handler = None
        self._logger = logger
        self.params = youtubedl_params
        self.proxy = self.get_main_proxy()

    def add_handler(self, handler: BackendHandler):
        if self._first_handler is None:
            self._first_handler = self._last_handler = handler
        else:
            self._last_handler = self._last_handler.set_next(handler)

    def get_main_proxy(self):
        proxies = urllib.request.getproxies()
        return (self.params.get('proxy')
                or proxies.get('http')
                or proxies.get('https'))

    def send_request(self, request: YDLRequest):
        if not request.proxy and self.proxy:
            request.proxy = self.proxy
        return self._first_handler.handle(request)


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


class YDLUniqueHTTPHeaderStore(YDLHTTPHeaderStore):
    def add_header(self, *args, **kwargs):
        return self.replace_header(*args, **kwargs)


"""
Youtube-dl request object
This is used for communication between the network backends and youtube-dl only

Network backends are responsible for validating and parsing the url, etc.
"""

# goes in YoutubeDL class?
def create_session(youtubedl_params, ydl_logger):
    adapters = [UnsupportedBackendHandler]
    session = Session(youtubedl_params, logger=ydl_logger)
    cookiejar = http.cookiejar.CookieJar()
    for adapter in adapters:
        if not adapter:
            continue
        session.add_handler(adapter(youtubedl_params, None, cookiejar))


# TODO: deal with msg in places where we don't always want to specify it
class RequestError(YoutubeDLError):
    def __init__(self, url, msg=None):
        super().__init__(msg)
        self.url = url


# TODO: Add tests for reading, closing, trying to read again etc.
# Test for making sure connection is released
# TODO: what parameters do we want? code/reason, response or both?
# Similar API as urllib.error.HTTPError
class HTTPError(RequestError, tempfile._TemporaryFileWrapper):
    def __init__(self, response: HTTPResponse, url):
        self.response = self.fp = response
        self.code = response.code
        msg = f'HTTP Error {self.code}: {response.reason}'
        if 400 <= self.code < 500:
            msg = '[Client Error] ' + msg
        elif 500 <= self.code < 600:
            msg = '[Server Error] ' + msg
        super().__init__(msg, url)
        tempfile._TemporaryFileWrapper.__init__(self, response, '<yt-dlp response>', delete=False)


class TransportError(RequestError):
    def __init__(self, url, msg=None, cause=None):
        if msg and cause:
            msg = msg + f' (caused by {cause!r})'  # TODO
        super().__init__(msg, url)
        self.cause = cause


class Timeout(RequestError):
    """Timeout error"""


class ReadTimeoutError(TransportError, Timeout):
    """timeout error occurred when reading data"""


class ConnectionTimeoutError(TransportError, Timeout):
    """timeout error occurred when trying to connect to server"""


class ResolveHostError(TransportError):
    def __init__(self, url, cause=None, host=None):
        msg = f'Failed to resolve host "{host or urllib.parse.urlparse(url).hostname}"'
        super().__init__(url, msg=msg, cause=cause)


class ConnectionReset(TransportError):
    msg = 'The connection was reset'


class IncompleteRead(TransportError, http.client.IncompleteRead):
    def __init__(self, url, partial, *, cause=None, expected=None):
        self.partial = partial
        self.expected = expected
        super().__init__(repr(self), url, cause)  # TODO: since we override with repr() in http.client.IncompleteRead


class SSLError(TransportError):
    pass


class ProxyError(TransportError):
    pass


class ContentDecodingError(RequestError):
    pass


class MaxRedirectsError(RequestError):
    pass

"""
RequestError
    HTTPError
    MaxRedirectsError
    SSLError
    TimeoutError
        ReadTimeoutError (also inherits transport error)
        ConnectionTimeoutError (also inherits transport error)
    
    TransportError
        ConnectionResetError
        ResolveHostError
        ProxyError
        SSLError
    ContentDecodingError
    MaxRedirectsError

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