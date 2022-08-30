from __future__ import annotations

import warnings

from .exceptions import UnsupportedRequest
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


def make_unavailable_rh(name, reason):
    class UnavailableRH(RequestHandler):
        NAME = name

        def prepare_request(self, request: Request):
            raise UnsupportedRequest(reason)

    return UnavailableRH


try:
    from ._requests import RequestsRH
except Exception as e:
    if not isinstance(e, ImportError):
        warnings.warn(f'Failed to import RequestsRH: {e}{bug_reports_message()}', OptionalDependencyWarning)
        RequestsRH = None
    else:
        RequestsRH = make_unavailable_rh('requests', str(e))

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
