from __future__ import annotations

import contextlib
import io
import logging
import ssl
import sys
import urllib.parse

from ._helper import (
    create_connection,
    create_socks_proxy_socket,
    make_socks_proxy_opts,
    select_proxy,
)
from .common import Features, Response, register_rh, register_preference
from .exceptions import (
    CertificateVerifyError,
    HTTPError,
    ProxyError,
    RequestError,
    SSLError,
    TransportError, UnsupportedRequest,
)
from .websocket import WebSocketRequestHandler, WebSocketResponse
from ..compat import functools
from ..dependencies import websocket_client, python_socks
from ..socks import ProxyError as SocksProxyError
from ..utils import int_or_none


if not websocket_client:
    raise ImportError('websocket-client is not installed')


websockets_version = tuple(map(int_or_none, websocket_client.__version__.split('.')))
# if websockets_version < (12, 0):
#     raise ImportError('Only websockets>=12.0 is supported')

import websockets.sync.client
from websockets.uri import parse_uri


class VoidCookieJar:
    # websockets-client for some reason has one global internal cookiejar
    # This is shared between all websocket instances.
    # We do not allow redirects for websockets currently, and we need the ability to have a "clear" session.
    # So we just patch it out with a dummy one ;)
    def add(self, cookie):
        pass

    def set(self, cookie):
        pass
    def get(self, name):
        return None


with contextlib.suppress(Exception):
    websocket_client._handshake.CookieJar = VoidCookieJar()
    pass


class WebsocketClientResponseAdapter(WebSocketResponse):

    def __init__(self, ws: websocket_client.Websocket, url):
        super().__init__(
            fp=io.BytesIO(),
            url=url,
            headers=ws.getheaders(),
            status=ws.getstatus(),
        )
        self._ws = ws

    def close(self):
        self._ws.shutdown()
        super().close()

    def send(self, message):
        # Try catch some common mistakes
        # todo: this should be in the base class?
        if not isinstance(message, (bytes, str)):
            raise TypeError('Message must be bytes or str')

        opcode = websocket_client.ABNF.OPCODE_TEXT
        if isinstance(message, bytes):
            opcode = websocket_client.ABNF.OPCODE_BINARY
        return self._ws.send(message, opcode)

    def recv(self):
        return self._ws.recv()


class WebsocketClientLoggingHandler(logging.StreamHandler):
    """Redirect websocket client logs to our logger"""

    def __init__(self, logger, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = logger

    def emit(self, record):
        try:
            msg = self.format(record)
            if record.levelno >= logging.ERROR:
                self._logger.error(msg)
            else:
                self._logger.stdout(msg)

        except Exception:
            self.handleError(record)

@register_rh
class WebsocketClientRH(WebSocketRequestHandler):
    """
    Websocket client request handler
    https://websocket-client.readthedocs.io
    https://github.com/websocket-client/websocket-client
    """
    _SUPPORTED_URL_SCHEMES = ('wss', 'ws')
    _SUPPORTED_PROXY_SCHEMES = ('http', 'socks4', 'socks4a', 'socks5', 'socks5h')
    _SUPPORTED_FEATURES = (Features.ALL_PROXY, Features.NO_PROXY)
    RH_NAME = 'websocket_client'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logging_handler = None
        if self.verbose:
            self.__logging_handler = WebsocketClientLoggingHandler(logger=self._logger)
            self.__logging_handler.setFormatter(logging.Formatter('websocket_client: %(message)s'))
            websocket_client.enableTrace(
                traceable=True,
                handler=self.__logging_handler,
                level='DEBUG'
            )

    def close(self):
        # Remove the logging handler that contains a reference to our logger
        # See: https://github.com/yt-dlp/yt-dlp/issues/8922
        if self.__logging_handler:
            logging.getLogger('websocket').removeHandler(self.__logging_handler)

    def _validate(self, request):
        super()._validate(request)
        if self.source_address:
            raise UnsupportedRequest('source_address is not supported')
        proxy = select_proxy(request.url, self._get_proxies(request))
        if not python_socks and proxy and urllib.parse.urlparse(proxy).scheme.lower().startswith('socks'):
            raise UnsupportedRequest('socks proxy support depends on python_socks')

    def _check_extensions(self, extensions):
        super()._check_extensions(extensions)
        extensions.pop('timeout', None)
        extensions.pop('cookiejar', None)

    def _send(self, request):
        timeout = self._calculate_timeout(request)
        headers = self._merge_headers(request.headers)
        if 'cookie' not in headers:
            cookiejar = self._get_cookiejar(request)
            cookie_header = cookiejar.get_cookie_header(request.url)
            if cookie_header:
                headers['cookie'] = cookie_header

        proxy = select_proxy(request.url, self._get_proxies(request))
        proxy_opts = {}
        if proxy:
            parsed_proxy = urllib.parse.urlparse(proxy)
            proxy_opts.update({
                'http_proxy_host': parsed_proxy.hostname,
                'http_proxy_port': parsed_proxy.port,
                'http_proxy_auth': (parsed_proxy.username, parsed_proxy.password),
                'proxy_type': parsed_proxy.scheme,
            })
        try:
            ws = websocket_client.WebSocket(sslopt={'context': self._make_sslcontext()})
            ws.connect(
                request.url,
                timeout=timeout,
                header=headers,
                # We don't support redirects on websocket connections.
                # note: if this is to be supported later, must consider proper cookie support.
                redirect_limit=0,
                # We handle no proxy handling ourselves.
                # websocket-client's behaviour may differ, so best we disable it.
                # https://github.com/websocket-client/websocket-client/issues/968
                http_no_proxy="__yt_dlp_invalid_no_proxy__",
                http_proxy_timeout=timeout,
                **proxy_opts

            )
        except ssl.SSLCertVerificationError as e:
            raise CertificateVerifyError(cause=e) from e
        except ssl.SSLError as e:
            raise SSLError(cause=e) from e
        except websocket_client.WebSocketBadStatusException as e:
            raise HTTPError(
                Response(
                    fp=io.BytesIO(e.resp_body or b''),
                    url=request.url,
                    headers=e.resp_headers,
                    status=e.status_code),
            ) from e
        except (
            python_socks.ProxyError,
            python_socks.ProxyTimeoutError,
            python_socks.ProxyConnectionError,
            websocket_client.WebSocketProxyException
        ) as e:
            raise ProxyError(cause=e) from e

        except OSError as e:
            # TimeoutError
            # todo: what other normal python errors are there?
            raise TransportError(cause=e) from e

        except websocket_client.WebSocketException as e:
            # todo: some of these are request errors
            raise TransportError(cause=e) from e

        # websocket_client does not raise an error when redirects exceeded
        if 300 < ws.status < 400:
            raise HTTPError(
                Response(
                    fp=io.BytesIO(b''),
                    url=request.url,
                    headers=ws.getheaders(),
                    status=ws.getstatus()),
            )

        return WebsocketClientResponseAdapter(ws, request.url)

@register_preference(WebsocketClientRH)
def websocket_client_preferenc(rh, request):
    return 50
