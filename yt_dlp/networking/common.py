from __future__ import unicode_literals
from __future__ import annotations

import collections
import email.policy
import inspect
import io
import ssl
import sys
import time
import typing
import urllib.parse
from email.message import Message
from http import HTTPStatus
import urllib.request
import urllib.response
from typing import Union, Type, List

from ..compat import compat_cookiejar, compat_str

from ..utils import (
    extract_basic_auth,
    escape_url,
    sanitize_url,
    write_string,
    std_headers,
    update_url_query,
    bug_reports_message,
    YoutubeDLError,
    RequestError,
    CaseInsensitiveDict,
    UnsupportedRequest
)

from .utils import random_user_agent

if typing.TYPE_CHECKING:
    from ..YoutubeDL import YoutubeDL


class Request:
    """
    Represents a request to be made.
    Partially backwards-compatible with urllib.request.Request.

    @param url: url to send. Will be sanitized and auth will be extracted as basic auth if present.
    @param data: payload data to send.
    @param headers: headers to send.
    @param proxies: proxy dict mapping of proto:proxy to use for the request and any redirects.
    @param query: URL query parameters to update the url with.
    @param method: HTTP method to use. If no method specified, will use POST if payload data is present else GET
    @param compression: whether to include content-encoding header on request.
    @param timeout: socket timeout value for this request.
    """
    def __init__(
            self,
            url: str,
            data=None,
            headers: typing.Mapping = None,
            proxies: dict = None,
            query: dict = None,
            method: str = None,
            compression: bool = True,
            timeout: Union[float, int] = None):

        url, basic_auth_header = extract_basic_auth(escape_url(sanitize_url(url)))

        if query:
            url = update_url_query(url, query)
        # rely on urllib Request's url parsing
        self.__request_store = urllib.request.Request(url)
        self.__method = method
        self._headers = CaseInsensitiveDict(headers)
        self._data = None
        self.data = data
        self.timeout = timeout

        if basic_auth_header:
            self.headers['Authorization'] = basic_auth_header

        self.proxies = proxies or {}
        self.compression = compression

    @property
    def url(self):
        return self.__request_store.full_url

    @url.setter
    def url(self, url):
        self.__request_store.full_url = url

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        # https://docs.python.org/3/library/urllib.request.html#urllib.request.Request.data
        if data != self._data:
            self._data = data
            if 'content-length' in self.headers:
                del self.headers['content-length']

    @property
    def headers(self) -> CaseInsensitiveDict:
        return self._headers

    @headers.setter
    def headers(self, new_headers: CaseInsensitiveDict):
        if not isinstance(new_headers, CaseInsensitiveDict):
            raise TypeError('headers must be a CaseInsensitiveDict')
        self._headers = new_headers

    @property
    def method(self):
        return self.__method or 'POST' if self.data is not None else 'GET'

    @method.setter
    def method(self, method: str):
        self.__method = method

    def copy(self):
        return type(self)(
            url=self.url, data=self.data, headers=self.headers.copy(), timeout=self.timeout,
            proxies=self.proxies.copy(), compression=self.compression, method=self.method)

    def add_header(self, key, value):
        self._headers[key] = value

    def get_header(self, key, default=None):
        return self._headers.get(key, default)

    @property
    def type(self):
        """URI scheme"""
        return self.__request_store.type

    @property
    def host(self):
        return self.__request_store.host

    # The following methods are for compatability reasons and are deprecated
    @property
    def fullurl(self):
        """Deprecated, use Request.url"""
        return self.url

    @fullurl.setter
    def fullurl(self, url):
        """Deprecated, use Request.url"""
        self.url = url

    def get_full_url(self):
        """Deprecated, use Request.url"""
        return self.url

    def get_method(self):
        """Deprecated, use Request.method"""
        return self.method

    def has_header(self, name):
        """Deprecated, use `name in Request.headers`"""
        return name in self.headers


class HEADRequest(Request):
    @property
    def method(self):
        return 'HEAD'


class PUTRequest(Request):
    @property
    def method(self):
        return 'PUT'


def update_request(req: Request, url: str = None, data=None,
                   headers: typing.Mapping = None, query: dict = None):
    """
    Creates a copy of the request and updates relevant fields
    """
    req = req.copy()
    req.data = data or req.data
    req.headers.update(headers or {})
    req.url = update_url_query(url or req.url, query or {})
    return req


class HTTPResponse(io.IOBase):
    """
    Abstract base class for HTTP response adapters.

    Interface partially backwards-compatible with addinfourl and http.client.HTTPResponse.

    @param raw: Original response.
    @param url: URL that this is a response of.
    @param headers: response headers.
    @param status: Response HTTP status code. Default is 200 OK.
    @param reason: HTTP status reason. Will use built-in reasons based on status code if not provided.
    """
    REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308]

    def __init__(
            self, raw,
            url: str,
            headers: typing.Mapping[str, str],
            status: int = 200,
            reason: typing.Optional[str] = None):

        self.raw = raw
        self.headers: Message = Message(policy=email.policy.HTTP)
        for name, value in (headers or {}).items():
            self.headers.add_header(name, value)
        self.status = status
        self.reason = reason
        self.url = url
        if not reason:
            try:
                self.reason = HTTPStatus(status).phrase
            except ValueError:
                pass

    def get_redirect_url(self):
        return self.headers.get('location') if self.status in self.REDIRECT_STATUS_CODES else None

    def readable(self):
        return True

    def read(self, amt: int = None):
        return self.raw.read(amt)

    def tell(self) -> int:
        return self.raw.tell()

    def close(self):
        self.raw.close()
        return super().close()

    # The following methods are for compatability reasons and are deprecated
    @property
    def code(self):
        """Deprecated, use HTTPResponse.status"""
        return self.status

    def getstatus(self):
        """Deprecated, use HTTPResponse.status"""
        return self.status

    def geturl(self):
        """Deprecated, use HTTPResponse.url"""
        return self.url

    def info(self):
        """Deprecated, use HTTPResponse.headers"""
        return self.headers


class RequestHandler:
    """
    Bare-bones request handler.
    Use this for defining custom protocols for extractors.
    """
    SUPPORTED_SCHEMES: list = None

    @classmethod
    def _check_scheme(cls, request: Request):
        scheme = urllib.parse.urlparse(request.url).scheme.lower()
        if scheme not in cls.SUPPORTED_SCHEMES:
            raise UnsupportedRequest(f'{scheme} scheme is not supported')

    def prepare_request(self, request: Request):
        """
        Prepare a request for this handler.
        If a request is unsupported, raises UnsupportedRequest
        """
        self._check_scheme(request)

    def handle(self, request: Request):
        """Method to handle given request. Redefine in subclasses"""

    @property
    def name(self):
        return type(self).__name__


class BackendRH(RequestHandler):
    """Network Backend adapter class
    Responsible for handling requests.
    """

    def __init__(self, ydl: YoutubeDL):
        self.ydl = ydl
        self.cookiejar = self.ydl.cookiejar

    # TODO: rework
    def to_screen(self, *args, **kwargs):
        self.ydl.to_stdout(*args, **kwargs)

    def to_stderr(self, message):
        self.ydl.to_stderr(message)

    def report_warning(self, *args, **kwargs):
        self.ydl.report_warning(*args, **kwargs)

    def report_error(self, *args, **kwargs):
        self.ydl.report_error(*args, **kwargs)

    def write_debug(self, *args, **kwargs):
        self.ydl.write_debug(*args, **kwargs)

    def make_sslcontext(self, **kwargs):
        """
        Make a new SSLContext configured for this backend.
        Note: _make_sslcontext must be implemented
        """
        context = self._make_sslcontext(
            verify=not self.ydl.params.get('nocheckcertificate'), **kwargs)
        if not context:
            return context
        if self.ydl.params.get('legacyserverconnect'):
            context.options |= 4  # SSL_OP_LEGACY_SERVER_CONNECT
        return context

    def _make_sslcontext(self, verify: bool, **kwargs) -> ssl.SSLContext:
        """Generate a backend-specific SSLContext. Redefine in subclasses"""

    def prepare_request(self, request: Request):
        super().prepare_request(request)
        request.headers = CaseInsensitiveDict(self.ydl.params.get('http_headers', {}), request.headers)
        if request.headers.get('Youtubedl-no-compression'):
            request.compression = False
            del request.headers['Youtubedl-no-compression']

        # Proxy preference: header req proxy > req proxies > ydl opt proxies > env proxies
        request.proxies = {**(self.ydl.proxies or {}), **(request.proxies or {})}
        req_proxy = request.headers.get('Ytdl-request-proxy')
        if req_proxy:
            del request.headers['Ytdl-request-proxy']
            request.proxies.update({'http': req_proxy, 'https': req_proxy})
        for k, v in request.proxies.items():
            if v == '__noproxy__':  # compat
                request.proxies[k] = None
        request.timeout = float(request.timeout or self.ydl.params.get('socket_timeout') or 20)  # do not accept 0
        self._prepare_request(request)

    def _prepare_request(self, request: Request):
        """Prepare a backend request. Redefine in subclasses."""


class RequestHandlerBroker:

    def __init__(self, ydl: YoutubeDL):
        self._handlers = []
        self.ydl: YoutubeDL = ydl

    def add_handler(self, handler: RequestHandler):
        if handler not in self._handlers and isinstance(handler, RequestHandler):
            self._handlers.append(handler)

    def remove_handler(self, handler: Union[RequestHandler, Type[RequestHandler]]):
        self._handlers = [h for h in self._handlers if not (isinstance(h, handler) or h is handler)]

    def get_handlers(self, handler: Type[RequestHandler] = None) -> List[RequestHandler]:
        return [h for h in self._handlers if isinstance(h, handler or RequestHandler)]

    # TODO: we want this available for RequestHandlers too
    # Ideally we would have some global logging object
    def to_debugtraffic(self, msg):
        if self.ydl.params.get('debug_printtraffic'):
            self.ydl.to_stdout(msg)

    def send(self, request: Union[Request, str, urllib.request.Request]) -> HTTPResponse:
        """
        Passes a request onto a suitable RequestHandler
        """
        if len(self._handlers) == 0:
            raise YoutubeDLError('No request handlers configured')
        if isinstance(request, str):
            request = Request(request)
        elif isinstance(request, urllib.request.Request):
            # compat
            request = Request(
                request.get_full_url(), data=request.data, method=request.get_method(),
                headers=CaseInsensitiveDict(request.headers, request.unredirected_hdrs))

        assert isinstance(request, Request)

        for handler in reversed(self._handlers):
            handler_req = request.copy()
            try:
                try:
                    handler.prepare_request(handler_req)
                    self.to_debugtraffic(f'Forwarding request to {handler.name} request handler')
                    res = handler.handle(handler_req)
                except RequestError as e:
                    e.handler = handler
                    raise
            # Nested try-except since we want to catch RequestErrors with handler attached
            except UnsupportedRequest as e:
                self.to_debugtraffic(
                    f'{handler.name} request handler cannot handle this request, trying next handler... (reason: {e})')
                continue
            except YoutubeDLError as e:
                self.ydl.report_warning(f'Unexpected error from request handler: {type(e).__name__}: {e}' + bug_reports_message())
                raise

            if not res:
                self.ydl.report_warning(f'{handler.name} request handler returned nothing for response' + bug_reports_message())
                continue
            assert isinstance(res, HTTPResponse)
            return res
        raise YoutubeDLError('No request handlers configured that could handle this request.')


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


# Use make_std_headers() to get a copy of these
_std_headers = CaseInsensitiveDict({
    'User-Agent': random_user_agent(),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-us,en;q=0.5',
    'Sec-Fetch-Mode': 'navigate',
})


# Get a copy of std headers, while also retaining backwards compat with utils.std_headers
def make_std_headers():
    return CaseInsensitiveDict(_std_headers, std_headers)
