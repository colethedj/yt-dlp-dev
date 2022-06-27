from __future__ import annotations

import itertools
import urllib.parse

from ._urllib import UrllibRH
from .common import (
    HEADRequest,
    PUTRequest,
    Request,
    RequestDirector,
    RequestHandler,
)

try:
    from ._requests import RequestsRH
except ImportError:
    RequestsRH = None


REQUEST_HANDLERS = [UrllibRH]

if RequestsRH is not None:
    REQUEST_HANDLERS.append(RequestsRH)

__all__ = ['UrllibRH', 'REQUEST_HANDLERS', 'Request', 'HEADRequest', 'PUTRequest', 'RequestDirector', 'RequestHandler', 'RequestsRH']
