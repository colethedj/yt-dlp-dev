import urllib.parse

from ._urllib import UrllibRH
from .common import BackendRH

from ..utils import RequestError

try:
    from ._requests import RequestsRH
    has_requests = True
except ImportError:
    has_requests = False
    RequestsRH = None


class UnsupportedRH(BackendRH):
    """
    Fallback backend adapter if a request is not supported.

    Add useful messages here of why the request may not be supported, if possible.
    E.g. a dependency is required.

    """
    def can_handle(self, request):
        scheme = urllib.parse.urlparse(request.url).scheme.lower()
        for rh in self.ydl.default_session.handlers:
            if rh.SUPPORTED_SCHEMES is not None and scheme in rh.SUPPORTED_SCHEMES:
                break
        else:
            raise RequestError(f'"{scheme}:" scheme is not supported')
        raise RequestError('This request is not supported')


REQUEST_HANDLERS = [UnsupportedRH, UrllibRH]
if RequestsRH is not None:
    REQUEST_HANDLERS.append(RequestsRH)

__all__ = ['UrllibRH', 'UnsupportedRH', 'REQUEST_HANDLERS']