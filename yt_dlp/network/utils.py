from __future__ import unicode_literals

import socket
import ssl
import sys


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
