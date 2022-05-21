from __future__ import annotations

import email.policy
import random
import ssl
import sys
import typing
from collections.abc import ItemsView, KeysView, ValuesView, MutableMapping
from email.message import Message

from ..compat import compat_urlparse, compat_urllib_parse_unquote_plus
from .socksproxy import ProxyType
import urllib.parse
try:
    import certifi
    has_certifi = True
except ImportError:
    has_certifi = False

if typing.TYPE_CHECKING:
    from .common import Request
    from http.cookiejar import CookieJar

import urllib.request


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


USER_AGENTS = {
    'Safari': 'Mozilla/5.0 (X11; Linux x86_64; rv:10.0) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
}


def _ssl_load_windows_store_certs(ssl_context, storename):
    # Code adapted from _load_windows_store_certs in https://github.com/python/cpython/blob/main/Lib/ssl.py
    try:
        certs = [cert for cert, encoding, trust in ssl.enum_certificates(storename)
                 if encoding == 'x509_asn' and (
                     trust is True or ssl.Purpose.SERVER_AUTH.oid in trust)]
    except PermissionError:
        return
    for cert in certs:
        try:
            ssl_context.load_verify_locations(cadata=cert)
        except ssl.SSLError:
            pass


def handle_youtubedl_headers(headers):
    filtered_headers = headers

    if 'Youtubedl-no-compression' in filtered_headers:
        filtered_headers = dict((k, v) for k, v in filtered_headers.items() if k.lower() != 'accept-encoding')
        del filtered_headers['Youtubedl-no-compression']

    return filtered_headers


def ssl_load_certs(context: ssl.SSLContext, params):
    if has_certifi and 'no-certifi' not in params.get('compat_opts', []):
        context.load_verify_locations(cafile=certifi.where())
    else:
        try:
            context.load_default_certs()
            # Work around the issue in load_default_certs when there are bad certificates. See:
            # https://github.com/yt-dlp/yt-dlp/issues/1060,
            # https://bugs.python.org/issue35665, https://bugs.python.org/issue45312
        except ssl.SSLError:
            # enum_certificates is not present in mingw python. See https://github.com/yt-dlp/yt-dlp/issues/1151
            if sys.platform == 'win32' and hasattr(ssl, 'enum_certificates'):
                # Create a new context to discard any certificates that were already loaded
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname, context.verify_mode = True, ssl.CERT_REQUIRED
                for storename in ('CA', 'ROOT'):
                    _ssl_load_windows_store_certs(context, storename)
            context.set_default_verify_paths()


def socks_create_proxy_args(socks_proxy):
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
    return {
        'proxytype': socks_type,
        'addr': url_components.hostname,
        'port': url_components.port or 1080,
        'rdns': True,
        'username': unquote_if_non_empty(url_components.username),
        'password': unquote_if_non_empty(url_components.password),
    }


def select_proxy(url, proxies):
    """Unified proxy selector for all backends"""
    if proxies is None:
        proxies = {}
    url_components = urllib.parse.urlparse(url)
    priority = [
        url_components.scheme or 'http',  # prioritise more specific mappings
        'all'
    ]
    return next((proxies[key] for key in priority if key in proxies), None)


class MultiHTTPHeaderDict(MutableMapping):
    """
    Wrapper for email.message.Message for only storing HTTP headers
    Allows storing multiple headers of the same name
    """
    _MESSAGE_CLS = Message

    def __init__(self, *data):
        self._data = self._MESSAGE_CLS(policy=email.policy.HTTP)
        for store in data:
            if hasattr(store, 'items'):
                self.add_headers(store)

    def add_headers(self, data):
        for k, v in data.items():
            self.add_header(k, v)

    def replace_headers(self, data):
        for k, v in data.items():
            self.replace_header(k, v)

    def add_header(self, _name: str, _value: str, **kwargs):
        return self._data.add_header(_name, _value, **kwargs)

    def replace_header(self, _name: str, _value: str):
        """
        Similar to add_header, but will replace all existing headers of such name if exists.
        Unlike email.Message, will add the header if it does not already exist.
        """
        try:
            return self._data.replace_header(_name, str(_value))
        except KeyError:
            return self._data.add_header(_name, _value)

    def get(self, name, default=None):
        return self._data.get(name, default)

    def copy(self):
        return self.__class__(self)

    def items(self):
        return self._data.items()

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def clear(self):
        return self._data._headers.clear()

    def __contains__(self, name):
        return name in self._data

    def __delitem__(self, name):
        del self._data[name]

    def __getitem__(self, name):
        return self.get(name)

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def __setitem__(self, name, val):
        self._data[name] = val

    def get_all(self, name, default=None):
        return self._data.get_all(name, default)

    def __str__(self):
        return str(self._data)


class HTTPHeaderDict(MultiHTTPHeaderDict):
    """
    Store and access headers case-insensitively.
    Accepts multiple dict-like instances in constructor, for easy merging

    Note: add_header and replace_header do the same thing
    """
    class _UniqueHeaderMessage(Message):
        def __setitem__(self, name, val):
            # __setitem__ in Message appends to the list of headers,
            # so we need to clear any existing headers of this key
            if name in self:
                del self[name]
            super().__setitem__(name, val)

    _MESSAGE_CLS = _UniqueHeaderMessage


def get_cookie_header(req: Request, cookiejar: CookieJar):
    cookie_req = urllib.request.Request(url=req.url)
    cookiejar.add_cookie_header(cookie_req)
    return cookie_req.get_header('Cookie')
