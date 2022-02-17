from ..common import YDLBackendHandler
from ...exceptions import RequestError

from ._urllib import UrllibHandler
try:
    from ._urllib3 import Urllib3Handler
    has_urllib3 = True
except ImportError:
    has_urllib3 = False
    Urllib3Handler = None


class UnsupportedBackendHandler(YDLBackendHandler):
    def can_handle(self, request, **req_kwargs):
        raise RequestError('This request is not supported')


network_handlers = [UnsupportedBackendHandler, UrllibHandler, Urllib3Handler]

__all__ = ['UrllibHandler', 'UnsupportedBackendHandler', 'network_handlers', 'Urllib3Handler', 'has_urllib3']
