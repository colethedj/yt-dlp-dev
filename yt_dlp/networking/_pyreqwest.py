from __future__ import annotations

import io

from ._helper import InstanceStoreMixin, select_proxy
from .common import (
    Request,
    Response,
    register_preference,
    register_rh, Features,
)
from .exceptions import (
    CertificateVerifyError,
    HTTPError,
    IncompleteRead,
    SSLError,
    TransportError, ProxyError,
)
from .impersonate import ImpersonateRequestHandler, ImpersonateTarget
from ..dependencies import pyreqwest_impersonate

if pyreqwest_impersonate is None:
    raise ImportError('pywequest_impersonate is not installed')


# pywequest_impersonate_version = tuple(map(int, re.split(r'[^\d]+', pyreqwest_impersonate.__version__)[:3]))

############################
# MISSING SUPPORT:

# Cookiejar sync (real cookie support that doesn't suck)
# Verbose logging (connection_verbose in client)
# Improved error handling
# Why is Content-Encoding always an empty string in response headers?
# Custom headers not being sent
# Support for source_address
# Exposed version attribute
# Streaming support
# Socks Ipv6 destination IP

@register_rh
class PyreqwestRH(ImpersonateRequestHandler, InstanceStoreMixin):
    RH_NAME = 'pyreqwest'
    _SUPPORTED_URL_SCHEMES = ('http', 'https')
    _SUPPORTED_FEATURES = (Features.ALL_PROXY,)
    _SUPPORTED_PROXY_SCHEMES = ('http', 'https', 'socks5', 'socks5h')
    _SUPPORTED_IMPERSONATE_TARGET_MAP = {
        ImpersonateTarget('chrome', '126'): 'chrome_126',
        ImpersonateTarget('chrome', '124'): 'chrome_124',
        ImpersonateTarget('chrome', '123'): 'chrome_123',
        ImpersonateTarget('chrome', '120'): 'chrome_120',
        ImpersonateTarget('chrome', '119'): 'chrome_119',
        ImpersonateTarget('chrome', '118'): 'chrome_118',
        ImpersonateTarget('chrome', '117'): 'chrome_117',
        ImpersonateTarget('chrome', '116'): 'chrome_116',
        ImpersonateTarget('chrome', '114'): 'chrome_114',
        ImpersonateTarget('chrome', '109'): 'chrome_109',
        ImpersonateTarget('chrome', '108'): 'chrome_108',
        ImpersonateTarget('chrome', '107'): 'chrome_107',
        ImpersonateTarget('chrome', '106'): 'chrome_106',
        ImpersonateTarget('chrome', '105'): 'chrome_105',
        ImpersonateTarget('chrome', '104'): 'chrome_104',
        ImpersonateTarget('chrome', '101'): 'chrome_101',
        ImpersonateTarget('chrome', '100'): 'chrome_100',
        ImpersonateTarget('safari', '17.5'): 'safari_17.5',
        ImpersonateTarget('safari', '17.4.1'): 'safari_17.4.1',
        ImpersonateTarget('safari', '17.2.1'): 'safari_17.2.1',
        ImpersonateTarget('safari', '16.5', 'ios'): 'safari_ios_16.5',
        ImpersonateTarget('safari', '16'): 'safari_16',
        ImpersonateTarget('safari', '15.6.1'): 'safari_15.6.1',
        ImpersonateTarget('safari', '15.5'): 'safari_15.5',
        ImpersonateTarget('safari', '15.3'): 'safari_15.3',
        ImpersonateTarget('edge', '122'): 'edge_122',
        ImpersonateTarget('edge', '101'): 'edge_101',
        ImpersonateTarget('edge', '99'): 'edge_99',
        ImpersonateTarget('okhttp', '5'): 'okhttp_5',
        ImpersonateTarget('okhttp', '4.10'): 'okhttp_4.10',
        ImpersonateTarget('okhttp', '4.9'): 'okhttp_4.9',
        ImpersonateTarget('okhttp', '3.14'): 'okhttp_3.14',
        ImpersonateTarget('okhttp', '3.13'): 'okhttp_3.13',
        ImpersonateTarget('okhttp', '3.11'): 'okhttp_3.11',
        ImpersonateTarget('okhttp', '3.9'): 'okhttp_3.9',
        ImpersonateTarget('safari', '17.2', 'ios'): 'safari_ios_17.2',
        ImpersonateTarget('safari', '17.4.1', 'ios'): 'safari_ios_17.4.1',
    }

    def _create_instance(self, impersonate=None, proxy=None):
        return pyreqwest_impersonate.Client(max_redirects=5, verify=self.verify, impersonate=impersonate, proxy=proxy)

    def _check_extensions(self, extensions):
        super()._check_extensions(extensions)
        extensions.pop('impersonate', None)
        extensions.pop('timeout', None)
        extensions.pop('legacy_ssl', None)

    def _send(self, request: Request):
        proxy = select_proxy(request.url, self._get_proxies(request))
        client = self._get_instance(
            impersonate=self._SUPPORTED_IMPERSONATE_TARGET_MAP.get(self._get_request_target(request)),
            proxy=proxy,
        )

        try:
            pyreqwest_res = client.request(
                method=request.method,
                url=request.url,
                headers=self._get_impersonate_headers(request),
                content=request.data,
                timeout=self._calculate_timeout(request),
            )
        except Exception as e:
            if 'too many redirects' in str(e):
                raise HTTPError(Response(
                    status=301,
                    url=request.url,
                    fp=io.BytesIO(),
                    headers={},
                ), redirect_loop=True)
            elif 'CERTIFICATE_VERIFY_FAILED' in str(e):
                raise CertificateVerifyError(cause=e) from e
            elif 'TLS handshake failed' in str(e):
                raise SSLError(cause=e) from e
            elif 'end of file before message length reached' in str(e):
                raise IncompleteRead(cause=e, partial=0, expected=0) from e
            elif any(m in str(e) for m in ['proxy authentication required', 'socks connect error']):
                raise ProxyError(cause=e) from e
            else:
                raise TransportError(cause=e) from e

        response = Response(
            fp=io.BytesIO(pyreqwest_res.content),
            headers=pyreqwest_res.headers,
            url=pyreqwest_res.url,
            status=pyreqwest_res.status_code,
        )

        if not 200 <= response.status < 300:
            raise HTTPError(response)

        return response


@register_preference(PyreqwestRH)
def pyreqwest_preference(_, __):
    return -50
