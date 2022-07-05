from __future__ import annotations

import warnings

from ..utils import bug_reports_message
from ._urllib import UrllibRH
from .common import (
    HEADRequest,
    PUTRequest,
    Request,
    RequestDirector,
    RequestHandler,
)

from ..dependencies import OptionalDependencyWarning

try:
    from ._requests import RequestsRH
except Exception as e:
    if not isinstance(e, ImportError):
        warnings.warn(f'Failed to import RequestsRH: {e}{bug_reports_message()}', OptionalDependencyWarning)
    RequestsRH = None

REQUEST_HANDLERS = [UrllibRH]

if RequestsRH is not None:
    REQUEST_HANDLERS.append(RequestsRH)

__all__ = [
    'UrllibRH',
    'REQUEST_HANDLERS',
    'Request',
    'HEADRequest',
    'PUTRequest',
    'RequestDirector',
    'RequestHandler',
    'RequestsRH'
]
