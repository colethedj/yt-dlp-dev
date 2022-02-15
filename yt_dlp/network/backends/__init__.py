from ..common import YDLBackendHandler
from ...exceptions import RequestError

from ._urllib import UrllibHandler
from ._urllib3 import Urllib3Handler, has_urllib3


class UnsupportedBackendHandler(YDLBackendHandler):
    def can_handle(self, request, **req_kwargs):
        raise RequestError('This request is not supported')


network_handlers = (UnsupportedBackendHandler, UrllibHandler, Urllib3Handler if has_urllib3 else None)

__all__ = ['UrllibHandler', 'UnsupportedBackendHandler', 'network_handlers', 'Urllib3Handler', 'has_urllib3']