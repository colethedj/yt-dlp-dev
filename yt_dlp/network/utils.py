from __future__ import unicode_literals

import base64
import re
import ssl
import sys

from ..compat import compat_urlparse, compat_urllib_parse_urlparse, \
    compat_urllib_parse
from ..utils import determine_ext


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


def make_ssl_context(params):
    opts_check_certificate = not params.get('nocheckcertificate')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = opts_check_certificate
    if params.get('legacyserverconnect'):
        context.options |= 4  # SSL_OP_LEGACY_SERVER_CONNECT
    context.verify_mode = ssl.CERT_REQUIRED if opts_check_certificate else ssl.CERT_NONE
    if opts_check_certificate:
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
    return context


def extract_basic_auth(url):
    parts = compat_urlparse.urlsplit(url)
    if parts.username is None:
        return url, None
    url = compat_urlparse.urlunsplit(parts._replace(netloc=(
        parts.hostname if parts.port is None
        else '%s:%d' % (parts.hostname, parts.port))))
    auth_payload = base64.b64encode(
        ('%s:%s' % (parts.username, parts.password or '')).encode('utf-8'))
    return url, 'Basic ' + auth_payload.decode('utf-8')


def sanitize_url(url):
    # Prepend protocol-less URLs with `http:` scheme in order to mitigate
    # the number of unwanted failures due to missing protocol
    if url.startswith('//'):
        return 'http:%s' % url
    # Fix some common typos seen so far
    COMMON_TYPOS = (
        # https://github.com/ytdl-org/youtube-dl/issues/15649
        (r'^httpss://', r'https://'),
        # https://bx1.be/lives/direct-tv/
        (r'^rmtp([es]?)://', r'rtmp\1://'),
    )
    for mistake, fixup in COMMON_TYPOS:
        if re.match(mistake, url):
            return re.sub(mistake, fixup, url)
    return url


def escape_url(url):
    """Escape URL as suggested by RFC 3986"""
    url_parsed = compat_urllib_parse_urlparse(url)
    return url_parsed._replace(
        netloc=url_parsed.netloc.encode('idna').decode('ascii'),
        path=escape_rfc3986(url_parsed.path),
        params=escape_rfc3986(url_parsed.params),
        query=escape_rfc3986(url_parsed.query),
        fragment=escape_rfc3986(url_parsed.fragment)
    ).geturl()


def determine_protocol(info_dict):
    protocol = info_dict.get('protocol')
    if protocol is not None:
        return protocol

    url = sanitize_url(info_dict['url'])
    if url.startswith('rtmp'):
        return 'rtmp'
    elif url.startswith('mms'):
        return 'mms'
    elif url.startswith('rtsp'):
        return 'rtsp'

    ext = determine_ext(url)
    if ext == 'm3u8':
        return 'm3u8'
    elif ext == 'f4m':
        return 'f4m'

    return compat_urllib_parse_urlparse(url).scheme


def escape_rfc3986(s):
    """Escape non-ASCII characters as suggested by RFC 3986"""
    return compat_urllib_parse.quote(s, b"%/;:@&=+$,!~*'()?#[]")


