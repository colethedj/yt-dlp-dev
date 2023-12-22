import base64
import copy
import io
import json
import uuid
import warnings
from collections.abc import Iterable
import re
import urllib.parse

from . import Request
from ._helper import select_proxy
from .common import register_rh, register_preference, Response, Features
from .exceptions import RequestError, CertificateVerifyError, TransportError, SSLError, ProxyError, HTTPError, \
    IncompleteRead, UnsupportedRequest
from .impersonate import ImpersonateRequestHandler, ImpersonateTarget

try:
    import ctypes
    import os
    tls_client = ctypes.cdll.LoadLibrary(os.getenv('YT_DLP_TLS_CLIENT_PATH'))
    tc_request = tls_client.request
    tc_request.argtypes = [ctypes.c_char_p]
    tc_request.restype = ctypes.c_char_p

    tc_getCookiesFromSession = tls_client.getCookiesFromSession
    tc_getCookiesFromSession.argtypes = [ctypes.c_char_p]
    tc_getCookiesFromSession.restype = ctypes.c_char_p

    tc_addCookiesToSession = tls_client.addCookiesToSession
    tc_addCookiesToSession.argtypes = [ctypes.c_char_p]
    tc_addCookiesToSession.restype = ctypes.c_char_p

    tc_freeMemory = tls_client.freeMemory
    tc_freeMemory.argtypes = [ctypes.c_char_p]

    tc_destroySession = tls_client.destroySession
    tc_destroySession.argtypes = [ctypes.c_char_p]
    tc_destroySession.restype = ctypes.c_char_p

    destroyAll = tls_client.destroyAll
    destroyAll.restype = ctypes.c_char_p

except Exception as e:
    warnings.warn(f'Failed to load tls-client: {e}')
    raise ImportError('tls-client unavailable')


@register_rh
class TLSClientRH(ImpersonateRequestHandler):
    # https://bogdanfinn.gitbook.io/open-source-oasis/tls-client

    """
    Known issues:
    - HTTP/1.1 impersonation is not supported (the site needs to support http/2) and upgrades don't work

    """
    _SUPPORTED_IMPERSONATE_TARGET_MAP = {
        ImpersonateTarget('chrome', '110', 'windows', '10'): {
            'tlsClientIdentifier': 'chrome_110',
            'headers': {
                # https://github.com/lwthiker/curl-impersonate/blob/main/chrome/curl_chrome110
                'sec-ch-ua': 'sec-ch-ua: "Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9'
            },
            'headerOrder': [
                'sec-ch-ua',
                'sec-ch-ua-mobile',
                'sec-ch-ua-platform',
                'upgrade-insecure-requests',
                'user-agent',
                'accept',
                'sec-fetch-site',
                'sec-fetch-mode',
                'sec-fetch-user',
                'sec-fetch-dest',
                'accept-encoding',
                'accept-language'
            ],
            'withRandomTLSExtensionOrder': True
        }
    }

    _SUPPORTED_URL_SCHEMES = ('http', 'https')
    _SUPPORTED_PROXY_SCHEMES = ('http', 'https', 'socks5h')
    _SUPPORTED_FEATURES = (Features.ALL_PROXY, Features.NO_PROXY)

    RH_NAME = 'tls_client'

    def _check_extensions(self, extensions):
        super()._check_extensions(extensions)
        extensions.pop('impersonate', None)
       # extensions.pop('cookiejar', None)
        extensions.pop('timeout', None)

    def _validate(self, request):
        if self._client_cert:
            raise UnsupportedRequest('Client certificates are not supported by tls-client')
        accept_encoding_header = self._merge_headers(request.headers).get('accept-encoding')
        if accept_encoding_header == 'identity':
            raise UnsupportedRequest('tls-client does not support streaming and this request may have a large response')
        super()._validate(request)

    @staticmethod
    def _parse_tc_response(tc_response):
        return json.loads(ctypes.string_at(tc_response).decode('utf-8'))

    def _make_tc_request(self, request_payload: dict, tc_method) -> dict:
        """
        Make a request to tls-client
        This will handle parsing the response and freeing memory

        :param request_payload: dict
        :param tc_method: ctypes function
        """
        tc_response = tc_method(json.dumps(request_payload).encode('utf-8'))
        response_object = self._parse_tc_response(tc_response)
        tc_freeMemory(response_object['id'].encode('utf-8'))
        return response_object

    def _destroy_session(self, session_id):
        response = self._make_tc_request({"sessionId": session_id}, tc_destroySession)
        if not response['success']:
            raise RequestError(f'Failed to destroy session: {response}')

    def _send(self, request: Request):
        # Session per request. This will not have persistent connections.
        session_id = str(uuid.uuid4())

        # go http client supports socks5h, but treats socks5 the same as socks5h [1].
        # However, tls-client does not accept socks5h and only socks5 (which is treated as socks5h) [2].
        # 1: https://github.com/golang/net/commit/395948e2f546cb82afa9e1f6d1a6e87849b9af1d
        # 2: https://github.com/bogdanfinn/tls-client/issues/67
        proxy = select_proxy(request.url, self._get_proxies(request))
        if proxy:
            proxy_parsed = urllib.parse.urlparse(proxy)
            if proxy_parsed.scheme == 'socks5h':
                proxy = proxy_parsed._replace(scheme='socks5').geturl()

        request_payload = (
            {
                **copy.deepcopy(self._get_mapped_request_target(request) or next(iter(self._SUPPORTED_IMPERSONATE_TARGET_MAP.values()))),
                'followRedirects': True,
                'insecureSkipVerify': not self.verify,
                'withDebug': self.verbose,
                'requestMethod': request.method,
                'requestUrl': request.url,
                'timeoutMilliseconds': int(self._calculate_timeout(request) * 1000),
                'sessionId': session_id,
                'isByteResponse': True,
                'proxyUrl': proxy,
                'isRotatingProxy': True,  # ?
                'localAddress': f'{self.source_address}:0' if self.source_address else None,

            })

        if request.data:
            request_body = request.data
            if isinstance(request.data, io.IOBase):
                request_body = request.data.read()
            elif isinstance(request.data, Iterable) and not isinstance(request.data, bytes):
                request_body = b''.join(request.data)

            request_payload.update(
                {
                    'requestBody': base64.urlsafe_b64encode(request_body).decode('utf-8'),
                    'isByteRequest': True,
                }
            )

        headers = self._get_impersonate_headers(request)
        if len(headers):
            request_payload['headers'].update(headers)
            request_payload['headerOrder'].extend(list(headers.keys()))

        response = self._make_tc_request(request_payload, tc_request)
        if response['status'] == 0:
            error = response['body']
            re_match = re.match(r'failed to do request: [^"]+"[^"]+":\s(.+)', error)
            request_error = re_match.group(1).lower() if re_match else ''
            if 'tls: failed to verify certificate' in request_error:
                raise CertificateVerifyError(request_error)
            elif 'tls:' in request_error:
                raise SSLError(request_error)
            elif re.match(r'proxy responded|socks connect', request_error):
                raise ProxyError(request_error)
            elif re.match(r'stopped after \d+ redirects', request_error):
                # no information about response available
                raise HTTPError(Response(fp=io.BytesIO(), url=request.url, headers={}, status=399), redirect_loop=True)
            elif error == 'unexpected EOF':
                raise IncompleteRead()
            raise TransportError(error)

        response_data = base64.urlsafe_b64decode(response['body'].split(',', 1)[1])

        self._destroy_session(session_id)

        res = Response(
            fp=io.BytesIO(response_data),
            url=response['target'],
            status=response['status'],
            headers={}
        )

        for header, values in response['headers'].items():
            for value in values:
                res.headers.add_header(header, value)
        if ',' in res.headers.get('content-encoding', ''):
            # what do we want to do in this situation?
            raise ValueError('Multiple content encodings are not supported')

        if not 200 <= res.status < 300:
            raise HTTPError(res, redirect_loop=False)

        return res


@register_preference(TLSClientRH)
def tls_client_preference(rh, request):
    return 100
