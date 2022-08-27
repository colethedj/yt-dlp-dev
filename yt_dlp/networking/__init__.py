from __future__ import annotations

from ._urllib import UrllibRH
from .common import (
    HEADRequest,
    PUTRequest,
    Request,
    RequestDirector,
    RequestHandler,
)


try:
    from ._websockets import WebsocketsRH
except Exception as e:
    WebsocketsRH = None


REQUEST_HANDLERS = [UrllibRH]

if WebsocketsRH is not None:
    REQUEST_HANDLERS.append(WebsocketsRH)

__all__ = ['UrllibRH', 'REQUEST_HANDLERS', 'Request', 'HEADRequest', 'PUTRequest', 'RequestDirector', 'RequestHandler']
