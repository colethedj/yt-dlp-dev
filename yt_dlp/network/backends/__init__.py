from ._urllib import UrllibHandler
from ..common import YDLBackendHandler


class UnsupportedBackendHandler(YDLBackendHandler):
    def can_handle(self, request, **req_kwargs):
        raise Exception('This request is not supported')


__all__ = ['UrllibHandler', 'UnsupportedBackendHandler']