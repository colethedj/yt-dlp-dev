from __future__ import unicode_literals

import collections
import io
import sys
import time
import urllib.parse
from abc import ABC, abstractmethod
from http import HTTPStatus
from email.message import Message
import urllib.request
import urllib.response

from ..compat import compat_cookiejar, compat_str

from ..utils import (
    extract_basic_auth,
    escape_url,
    sanitize_url,
    write_string
)


class YDLRequest:
    """
    Our own request class, similar to urllib.request.Request
    This is used to send request information from youtube-dl to the backends.
    Backends are expected to extract relevant data from this object rather that use it directly (e.g. passing to urllib)
    """
    def __init__(
            self, url, data=None, headers=None, proxy=None, compression=True, method=None,
            unverifiable=False, unredirected_headers=None, origin_req_host=None, timeout=None):
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
        self.timeout = timeout

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


def req_to_ydlreq(req: urllib.request.Request):
    return YDLRequest(
        req.get_full_url(), data=req.data, headers=req.headers, method=req.get_method(),
        unverifiable=req.unverifiable, unredirected_headers=req.unredirected_hdrs,
        origin_req_host=req.origin_req_host)


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

    def __init__(self, headers, status, version=None, reason=None):
        self.headers = YDLHTTPHeaderStore(headers)
        self.status = self.code = status
        self.reason = reason
        if not reason:
            try:
                self.reason = HTTPStatus(status).name.replace('_', ' ').title()
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
        self.cookiejar = cookies

        # TODO: The following can probably be delegated to YoutubeDL._create_session
        timeout_val = self.params.get('socket_timeout')
        self.debuglevel = 1 if self.params.get('debug_printtraffic') else 0
        self.socket_timeout = 20 if timeout_val is None else float(timeout_val)

        self._initialize()

    def _initialize(self):
        """Initialization process. Redefine in subclasses."""
        pass

    def set_next(self, handler):
        self._next_handler = handler

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


class Session:

    def __init__(self, youtubedl_params: dict, logger):
        self._handler = None
        self._logger = logger
        self.params = youtubedl_params
        self.proxy = self.get_main_proxy()

    def add_handler(self, handler: YDLBackendHandler):

        if self._handler is None:
            self._handler = handler
        else:
            handler.set_next(self._handler)
            self._handler = handler

    def get_main_proxy(self):
        proxies = urllib.request.getproxies()
        return (self.params.get('proxy')
                or proxies.get('http')
                or proxies.get('https'))

    def send_request(self, request: YDLRequest):
        if not request.proxy and self.proxy:
            request.proxy = self.proxy
        return self._handler.handle(request)


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

    """
    Message requires value to be a str, but some extractors provide headers as integers.
    """
    def add_header(self, _name: str, _value: str, **kwargs):
        return super().add_header(_name, str(_value) if isinstance(_value, int) else _value, **kwargs)

    def replace_header(self, _name: str, _value: str, **kwargs):
        return super().add_header(_name, str(_value) if isinstance(_value, int) else _value, **kwargs)


class YDLUniqueHTTPHeaderStore(YDLHTTPHeaderStore):
    def add_header(self, *args, **kwargs):
        try:
            return self.replace_header(*args, **kwargs)
        except KeyError:
            return super().add_header(*args, **kwargs)

"""
Youtube-dl request object
This is used for communication between the network backends and youtube-dl only

Network backends are responsible for validating and parsing the url, etc.
"""


class YoutubeDLCookieJar(compat_cookiejar.MozillaCookieJar):
    """
    See [1] for cookie file format.

    1. https://curl.haxx.se/docs/http-cookies.html
    """
    _HTTPONLY_PREFIX = '#HttpOnly_'
    _ENTRY_LEN = 7
    _HEADER = '''# Netscape HTTP Cookie File
# This file is generated by yt-dlp.  Do not edit.

'''
    _CookieFileEntry = collections.namedtuple(
        'CookieFileEntry',
        ('domain_name', 'include_subdomains', 'path', 'https_only', 'expires_at', 'name', 'value'))

    def save(self, filename=None, ignore_discard=False, ignore_expires=False):
        """
        Save cookies to a file.

        Most of the code is taken from CPython 3.8 and slightly adapted
        to support cookie files with UTF-8 in both python 2 and 3.
        """
        if filename is None:
            if self.filename is not None:
                filename = self.filename
            else:
                raise ValueError(compat_cookiejar.MISSING_FILENAME_TEXT)

        # Store session cookies with `expires` set to 0 instead of an empty
        # string
        for cookie in self:
            if cookie.expires is None:
                cookie.expires = 0

        with io.open(filename, 'w', encoding='utf-8') as f:
            f.write(self._HEADER)
            now = time.time()
            for cookie in self:
                if not ignore_discard and cookie.discard:
                    continue
                if not ignore_expires and cookie.is_expired(now):
                    continue
                if cookie.secure:
                    secure = 'TRUE'
                else:
                    secure = 'FALSE'
                if cookie.domain.startswith('.'):
                    initial_dot = 'TRUE'
                else:
                    initial_dot = 'FALSE'
                if cookie.expires is not None:
                    expires = compat_str(cookie.expires)
                else:
                    expires = ''
                if cookie.value is None:
                    # cookies.txt regards 'Set-Cookie: foo' as a cookie
                    # with no name, whereas http.cookiejar regards it as a
                    # cookie with no value.
                    name = ''
                    value = cookie.name
                else:
                    name = cookie.name
                    value = cookie.value
                f.write(
                    '\t'.join([cookie.domain, initial_dot, cookie.path,
                               secure, expires, name, value]) + '\n')

    def load(self, filename=None, ignore_discard=False, ignore_expires=False):
        """Load cookies from a file."""
        if filename is None:
            if self.filename is not None:
                filename = self.filename
            else:
                raise ValueError(compat_cookiejar.MISSING_FILENAME_TEXT)

        def prepare_line(line):
            if line.startswith(self._HTTPONLY_PREFIX):
                line = line[len(self._HTTPONLY_PREFIX):]
            # comments and empty lines are fine
            if line.startswith('#') or not line.strip():
                return line
            cookie_list = line.split('\t')
            if len(cookie_list) != self._ENTRY_LEN:
                raise compat_cookiejar.LoadError('invalid length %d' % len(cookie_list))
            cookie = self._CookieFileEntry(*cookie_list)
            if cookie.expires_at and not cookie.expires_at.isdigit():
                raise compat_cookiejar.LoadError('invalid expires at %s' % cookie.expires_at)
            return line

        cf = io.StringIO()
        with io.open(filename, encoding='utf-8') as f:
            for line in f:
                try:
                    cf.write(prepare_line(line))
                except compat_cookiejar.LoadError as e:
                    write_string(
                        'WARNING: skipping cookie file entry due to %s: %r\n'
                        % (e, line), sys.stderr)
                    continue
        cf.seek(0)
        self._really_load(cf, filename, ignore_discard, ignore_expires)
        # Session cookies are denoted by either `expires` field set to
        # an empty string or 0. MozillaCookieJar only recognizes the former
        # (see [1]). So we need force the latter to be recognized as session
        # cookies on our own.
        # Session cookies may be important for cookies-based authentication,
        # e.g. usually, when user does not check 'Remember me' check box while
        # logging in on a site, some important cookies are stored as session
        # cookies so that not recognizing them will result in failed login.
        # 1. https://bugs.python.org/issue17164
        for cookie in self:
            # Treat `expires=0` cookies as session cookies
            if cookie.expires == 0:
                cookie.expires = None
                cookie.discard = True