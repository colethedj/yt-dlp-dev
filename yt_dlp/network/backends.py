from __future__ import unicode_literals

import collections
import contextlib
import functools
import gzip
import io
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
import random
import zlib

from .common import (
    HTTPResponse,
    IncompleteRead,
    ReadTimeoutError,
    TransportError,
    ConnectionReset,
    YDLBackendHandler, YDLRequest,
    HTTPError,
    ConnectionTimeoutError, ResolveHostError,
    SSLError, HEADRequest
)
import http.client

from .socksproxy import ProxyType, sockssocket
from .utils import make_ssl_context
from ..compat import compat_urllib_request_DataHandler, compat_urllib_request, compat_http_client, compat_brotli, \
    compat_urlparse, compat_urllib_parse_unquote_plus, compat_cookiejar, compat_str, compat_HTTPError
from ..utils import (
    std_headers, escape_url, UnsupportedError, bug_reports_message, update_url_query
)

from ..compat import compat_brotli


class HttplibResponseAdapter(HTTPResponse):
    def __init__(self, res: http.client.HTTPResponse):
        self._res = res
        super().__init__(
            headers=res.headers, status=res.status,
            version=res.version if hasattr(res, 'version') else None)

    def geturl(self):
        return self._res.geturl()

    def read(self, amt=None):
        try:
            return self._res.read(amt)
        # TODO: handle exceptions
        except http.client.IncompleteRead as err:
            raise IncompleteRead(err.partial, self.geturl(), cause=err, expected=err.expected) from err
        except ConnectionResetError as err:
            raise ConnectionReset(self.geturl(), cause=err) from err
        except socket.timeout as err:
            raise ReadTimeoutError(self.geturl(), cause=err) from err
        except (OSError, http.client.HTTPException) as err:
            raise TransportError(self.geturl(), cause=err) from err

    def close(self):
        super().close()
        return self._res.close()

    def tell(self) -> int:
        return self._res.tell()


def random_user_agent():
    _USER_AGENT_TPL = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36'
    _CHROME_VERSIONS = (
        '90.0.4430.212',
        '90.0.4430.24',
        '90.0.4430.70',
        '90.0.4430.72',
        '90.0.4430.85',
        '90.0.4430.93',
        '91.0.4472.101',
        '91.0.4472.106',
        '91.0.4472.114',
        '91.0.4472.124',
        '91.0.4472.164',
        '91.0.4472.19',
        '91.0.4472.77',
        '92.0.4515.107',
        '92.0.4515.115',
        '92.0.4515.131',
        '92.0.4515.159',
        '92.0.4515.43',
        '93.0.4556.0',
        '93.0.4577.15',
        '93.0.4577.63',
        '93.0.4577.82',
        '94.0.4606.41',
        '94.0.4606.54',
        '94.0.4606.61',
        '94.0.4606.71',
        '94.0.4606.81',
        '94.0.4606.85',
        '95.0.4638.17',
        '95.0.4638.50',
        '95.0.4638.54',
        '95.0.4638.69',
        '95.0.4638.74',
        '96.0.4664.18',
        '96.0.4664.45',
        '96.0.4664.55',
        '96.0.4664.93',
        '97.0.4692.20',
    )
    return _USER_AGENT_TPL % random.choice(_CHROME_VERSIONS)

URLLIB_SUPPORTED_ENCODINGS = [
    'gzip', 'deflate'
]
if compat_brotli:
    URLLIB_SUPPORTED_ENCODINGS.append('br')

urllib_std_headers = {
    'User-Agent': random_user_agent(),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': ', '.join(URLLIB_SUPPORTED_ENCODINGS),
    'Accept-Language': 'en-us,en;q=0.5',
    'Sec-Fetch-Mode': 'navigate',
}


class UrllibHandler(YDLBackendHandler):
    _SUPPORTED_PROTOCOLS = ['http', 'https']

    def _initialize(self):
        cookie_processor = YoutubeDLCookieProcessor(self.cookiejar)
        proxy_handler = PerRequestProxyHandler()
        debuglevel = 1 if self.params.get('debug_printtraffic') else 0
        https_handler = make_HTTPS_handler(self.params, debuglevel=debuglevel)
        ydlh = YoutubeDLHandler(self.params, debuglevel=debuglevel)
        redirect_handler = YoutubeDLRedirectHandler()
        data_handler = compat_urllib_request_DataHandler()

        # TODO: technically the following is not required now, but will keep in for now
        # When passing our own FileHandler instance, build_opener won't add the
        # default FileHandler and allows us to disable the file protocol, which
        # can be used for malicious purposes (see
        # https://github.com/ytdl-org/youtube-dl/issues/8227)
        file_handler = urllib.request.FileHandler()
        def file_open(*args, **kwargs):
            raise urllib.error.URLError('file:// scheme is explicitly disabled in yt-dlp for security reasons')
        file_handler.file_open = file_open
        opener = urllib.request.build_opener(
            proxy_handler, https_handler, cookie_processor, ydlh, redirect_handler, data_handler, file_handler)
        # Delete the default user-agent header, which would otherwise apply in
        # cases where our custom HTTP handler doesn't come into play
        # (See https://github.com/ytdl-org/youtube-dl/issues/1309 for details)
        opener.addheaders = []
        self._opener = opener

    def _real_handle(self, request: YDLRequest, **kwargs) -> HTTPResponse:
        urllib_req = urllib.request.Request(
            url=request.url, data=request.data, headers=dict(request.headers), origin_req_host=request.origin_req_host,
            unverifiable=request.unverifiable, method=request.method
        )

        if not request.compression:
            urllib_req.add_header('Youtubedl-no-compression', True)
        if request.proxy:
            urllib_req.add_header('Ytdl-request-proxy',request.proxy)
        try:
            res = self._opener.open(urllib_req, timeout=request.timeout or self.socket_timeout)

        except urllib.error.HTTPError as e:
            # TODO: create a HTTPResponse from HTTPError
            raise NotImplementedError

        except urllib.error.URLError as e:
            url = e.filename
            # TODO: what errors are raised outside URLError?
            try:
                raise e.reason from e
            except TimeoutError as e:
                raise ConnectionTimeoutError(url=url, cause=e) from e
            except socket.gaierror as e:
                raise ResolveHostError(url=url, cause=e) from e
            except ssl.SSLError as e:
                raise SSLError(url=url, cause=e) from e
            except:
                raise TransportError(url=url, cause=e) from e

        except http.client.HTTPException as e:
            raise TransportError(cause=e) from e
        return HttplibResponseAdapter(res)


def make_HTTPS_handler(params, **kwargs):
    return YoutubeDLHTTPSHandler(params, context=make_ssl_context(params), **kwargs)


def _create_http_connection(ydl_handler, http_class, is_https, *args, **kwargs):
    hc = http_class(*args, **kwargs)
    source_address = ydl_handler._params.get('source_address')

    if source_address is not None:
        # This is to workaround _create_connection() from socket where it will try all
        # address data from getaddrinfo() including IPv6. This filters the result from
        # getaddrinfo() based on the source_address value.
        # This is based on the cpython socket.create_connection() function.
        # https://github.com/python/cpython/blob/master/Lib/socket.py#L691
        def _create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
            host, port = address
            err = None
            addrs = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
            af = socket.AF_INET if '.' in source_address[0] else socket.AF_INET6
            ip_addrs = [addr for addr in addrs if addr[0] == af]
            if addrs and not ip_addrs:
                ip_version = 'v4' if af == socket.AF_INET else 'v6'
                raise socket.error(
                    "No remote IP%s addresses available for connect, can't use '%s' as source address"
                    % (ip_version, source_address[0]))
            for res in ip_addrs:
                af, socktype, proto, canonname, sa = res
                sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                        sock.settimeout(timeout)
                    sock.bind(source_address)
                    sock.connect(sa)
                    err = None  # Explicitly break reference cycle
                    return sock
                except socket.error as _:
                    err = _
                    if sock is not None:
                        sock.close()
            if err is not None:
                raise err
            else:
                raise socket.error('getaddrinfo returns an empty list')
        if hasattr(hc, '_create_connection'):
            hc._create_connection = _create_connection
        sa = (source_address, 0)
        if hasattr(hc, 'source_address'):  # Python 2.7+
            hc.source_address = sa
        else:  # Python 2.6
            def _hc_connect(self, *args, **kwargs):
                sock = _create_connection(
                    (self.host, self.port), self.timeout, sa)
                if is_https:
                    self.sock = ssl.wrap_socket(
                        sock, self.key_file, self.cert_file,
                        ssl_version=ssl.PROTOCOL_TLSv1)
                else:
                    self.sock = sock
            hc.connect = functools.partial(_hc_connect, hc)

    return hc


def handle_youtubedl_headers(headers):
    filtered_headers = headers

    if 'Youtubedl-no-compression' in filtered_headers:
        filtered_headers = dict((k, v) for k, v in filtered_headers.items() if k.lower() != 'accept-encoding')
        del filtered_headers['Youtubedl-no-compression']

    return filtered_headers


class YoutubeDLHandler(compat_urllib_request.HTTPHandler):
    """Handler for HTTP requests and responses.

    This class, when installed with an OpenerDirector, automatically adds
    the standard headers to every HTTP request and handles gzipped and
    deflated responses from web servers. If compression is to be avoided in
    a particular request, the original request in the program code only has
    to include the HTTP header "Youtubedl-no-compression", which will be
    removed before making the real request.

    Part of this code was copied from:

    http://techknack.net/python-urllib2-handlers/

    Andrew Rowls, the author of that code, agreed to release it to the
    public domain.
    """

    def __init__(self, params, *args, **kwargs):
        compat_urllib_request.HTTPHandler.__init__(self, *args, **kwargs)
        self._params = params

    def http_open(self, req):
        conn_class = compat_http_client.HTTPConnection

        socks_proxy = req.headers.get('Ytdl-socks-proxy')
        if socks_proxy:
            conn_class = make_socks_conn_class(conn_class, socks_proxy)
            del req.headers['Ytdl-socks-proxy']

        return self.do_open(functools.partial(
            _create_http_connection, self, conn_class, False),
            req)

    @staticmethod
    def deflate(data):
        if not data:
            return data
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except zlib.error:
            return zlib.decompress(data)

    def http_request(self, req):
        # According to RFC 3986, URLs can not contain non-ASCII characters, however this is not
        # always respected by websites, some tend to give out URLs with non percent-encoded
        # non-ASCII characters (see telemb.py, ard.py [#3412])
        # urllib chokes on URLs with non-ASCII characters (see http://bugs.python.org/issue3991)
        # To work around aforementioned issue we will replace request's original URL with
        # percent-encoded one
        # Since redirects are also affected (e.g. http://www.southpark.de/alle-episoden/s18e09)
        # the code of this workaround has been moved here from YoutubeDL.urlopen()
        url = req.get_full_url()
        url_escaped = escape_url(url)

        # Substitute URL if any change after escaping
        if url != url_escaped:
            req = update_Request(req, url=url_escaped)

        for h, v in std_headers.items():
            # Capitalize is needed because of Python bug 2275: http://bugs.python.org/issue2275
            # The dict keys are capitalized because of this bug by urllib
            if h.capitalize() not in req.headers:
                req.add_header(h, v)

        req.headers = handle_youtubedl_headers(req.headers)

        return req

    def http_response(self, req, resp):
        old_resp = resp
        # gzip
        if resp.headers.get('Content-encoding', '') == 'gzip':
            content = resp.read()
            gz = gzip.GzipFile(fileobj=io.BytesIO(content), mode='rb')
            try:
                uncompressed = io.BytesIO(gz.read())
            except IOError as original_ioerror:
                # There may be junk add the end of the file
                # See http://stackoverflow.com/q/4928560/35070 for details
                for i in range(1, 1024):
                    try:
                        gz = gzip.GzipFile(fileobj=io.BytesIO(content[:-i]), mode='rb')
                        uncompressed = io.BytesIO(gz.read())
                    except IOError:
                        continue
                    break
                else:
                    raise original_ioerror
            resp = compat_urllib_request.addinfourl(uncompressed, old_resp.headers, old_resp.url, old_resp.code)
            resp.msg = old_resp.msg
            del resp.headers['Content-encoding']
        # deflate
        if resp.headers.get('Content-encoding', '') == 'deflate':
            gz = io.BytesIO(self.deflate(resp.read()))
            resp = compat_urllib_request.addinfourl(gz, old_resp.headers, old_resp.url, old_resp.code)
            resp.msg = old_resp.msg
            del resp.headers['Content-encoding']
        # brotli
        if resp.headers.get('Content-encoding', '') == 'br':
            if not compat_brotli:
                raise UnsupportedError(
                    'brotli encoding should not have been requested as decoding requires brotlicffi or brotli library' + bug_reports_message())
            resp = compat_urllib_request.addinfourl(
                io.BytesIO(compat_brotli.decompress(resp.read())), old_resp.headers, old_resp.url, old_resp.code)
            resp.msg = old_resp.msg
            del resp.headers['Content-encoding']
        # Percent-encode redirect URL of Location HTTP header to satisfy RFC 3986 (see
        # https://github.com/ytdl-org/youtube-dl/issues/6457).
        if 300 <= resp.code < 400:
            location = resp.headers.get('Location')
            if location:
                # As of RFC 2616 default charset is iso-8859-1 that is respected by python 3
                location = location.encode('iso-8859-1').decode('utf-8')
                location_escaped = escape_url(location)
                if location != location_escaped:
                    del resp.headers['Location']
                    resp.headers['Location'] = location_escaped
        return resp

    https_request = http_request
    https_response = http_response


def make_socks_conn_class(base_class, socks_proxy):
    assert issubclass(base_class, (
        compat_http_client.HTTPConnection, compat_http_client.HTTPSConnection))

    url_components = compat_urlparse.urlparse(socks_proxy)
    if url_components.scheme.lower() == 'socks5':
        socks_type = ProxyType.SOCKS5
    elif url_components.scheme.lower() in ('socks', 'socks4'):
        socks_type = ProxyType.SOCKS4
    elif url_components.scheme.lower() == 'socks4a':
        socks_type = ProxyType.SOCKS4A

    def unquote_if_non_empty(s):
        if not s:
            return s
        return compat_urllib_parse_unquote_plus(s)

    proxy_args = (
        socks_type,
        url_components.hostname, url_components.port or 1080,
        True,  # Remote DNS
        unquote_if_non_empty(url_components.username),
        unquote_if_non_empty(url_components.password),
    )

    class SocksConnection(base_class):
        def connect(self):
            self.sock = sockssocket()
            self.sock.setproxy(*proxy_args)
            if type(self.timeout) in (int, float):
                self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

            if isinstance(self, compat_http_client.HTTPSConnection):
                if hasattr(self, '_context'):  # Python > 2.6
                    self.sock = self._context.wrap_socket(
                        self.sock, server_hostname=self.host)
                else:
                    self.sock = ssl.wrap_socket(self.sock)

    return SocksConnection


class YoutubeDLHTTPSHandler(compat_urllib_request.HTTPSHandler):
    def __init__(self, params, https_conn_class=None, *args, **kwargs):
        compat_urllib_request.HTTPSHandler.__init__(self, *args, **kwargs)
        self._https_conn_class = https_conn_class or compat_http_client.HTTPSConnection
        self._params = params

    def https_open(self, req):
        kwargs = {}
        conn_class = self._https_conn_class

        if hasattr(self, '_context'):  # python > 2.6
            kwargs['context'] = self._context
        if hasattr(self, '_check_hostname'):  # python 3.x
            kwargs['check_hostname'] = self._check_hostname

        socks_proxy = req.headers.get('Ytdl-socks-proxy')
        if socks_proxy:
            conn_class = make_socks_conn_class(conn_class, socks_proxy)
            del req.headers['Ytdl-socks-proxy']

        return self.do_open(functools.partial(
            _create_http_connection, self, conn_class, True),
            req, **kwargs)


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


class YoutubeDLCookieProcessor(compat_urllib_request.HTTPCookieProcessor):
    def __init__(self, cookiejar=None):
        compat_urllib_request.HTTPCookieProcessor.__init__(self, cookiejar)

    def http_response(self, request, response):
        return compat_urllib_request.HTTPCookieProcessor.http_response(self, request, response)

    https_request = compat_urllib_request.HTTPCookieProcessor.http_request
    https_response = http_response


class YoutubeDLRedirectHandler(compat_urllib_request.HTTPRedirectHandler):
    """YoutubeDL redirect handler

    The code is based on HTTPRedirectHandler implementation from CPython [1].

    This redirect handler solves two issues:
     - ensures redirect URL is always unicode under python 2
     - introduces support for experimental HTTP response status code
       308 Permanent Redirect [2] used by some sites [3]

    1. https://github.com/python/cpython/blob/master/Lib/urllib/request.py
    2. https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308
    3. https://github.com/ytdl-org/youtube-dl/issues/28768
    """

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = compat_urllib_request.HTTPRedirectHandler.http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return a Request or None in response to a redirect.

        This is called by the http_error_30x methods when a
        redirection response is received.  If a redirection should
        take place, return a new Request to allow http_error_30x to
        perform the redirect.  Otherwise, raise HTTPError if no-one
        else should try to handle this url.  Return None if you can't
        but another Handler might.
        """
        m = req.get_method()
        if (not (code in (301, 302, 303, 307, 308) and m in ("GET", "HEAD")
                 or code in (301, 302, 303) and m == "POST")):
            raise compat_HTTPError(req.full_url, code, msg, headers, fp)
        # Strictly (according to RFC 2616), 301 or 302 in response to
        # a POST MUST NOT cause a redirection without confirmation
        # from the user (of urllib.request, in this case).  In practice,
        # essentially all clients do redirect in this case, so we do
        # the same.

        # Be conciliant with URIs containing a space.  This is mainly
        # redundant with the more complete encoding done in http_error_302(),
        # but it is kept for compatibility with other callers.
        newurl = newurl.replace(' ', '%20')

        CONTENT_HEADERS = ("content-length", "content-type")
        # NB: don't use dict comprehension for python 2.6 compatibility
        newheaders = dict((k, v) for k, v in req.headers.items()
                          if k.lower() not in CONTENT_HEADERS)
        return compat_urllib_request.Request(
            newurl, headers=newheaders, origin_req_host=req.origin_req_host,
            unverifiable=True)


def update_Request(req, url=None, data=None, headers={}, query={}):
    class PUTRequest(compat_urllib_request.Request):
        def get_method(self):
            return 'PUT'
    req_headers = req.headers.copy()
    req_headers.update(headers)
    req_data = data or req.data
    req_url = update_url_query(url or req.get_full_url(), query)
    req_get_method = req.get_method()
    if req_get_method == 'HEAD':
        req_type = HEADRequest
    elif req_get_method == 'PUT':
        req_type = PUTRequest
    else:
        req_type = compat_urllib_request.Request
    new_req = req_type(
        req_url, data=req_data, headers=req_headers,
        origin_req_host=req.origin_req_host, unverifiable=req.unverifiable)
    if hasattr(req, 'timeout'):
        new_req.timeout = req.timeout
    return new_req


class PerRequestProxyHandler(compat_urllib_request.ProxyHandler):
    def __init__(self, proxies=None):
        # Set default handlers
        for type in ('http', 'https'):
            setattr(self, '%s_open' % type,
                    lambda r, proxy='__noproxy__', type=type, meth=self.proxy_open:
                        meth(r, proxy, type))
        compat_urllib_request.ProxyHandler.__init__(self, proxies)

    def proxy_open(self, req, proxy, type):
        req_proxy = req.headers.get('Ytdl-request-proxy')
        if req_proxy is not None:
            proxy = req_proxy
            del req.headers['Ytdl-request-proxy']

        if proxy == '__noproxy__':
            return None  # No Proxy
        if compat_urlparse.urlparse(proxy).scheme.lower() in ('socks', 'socks4', 'socks4a', 'socks5'):
            req.add_header('Ytdl-socks-proxy', proxy)
            # yt-dlp's http/https handlers do wrapping the socket with socks
            return None
        return compat_urllib_request.ProxyHandler.proxy_open(
            self, req, proxy, type)