import inspect

import pytest

from yt_dlp.networking import RequestHandler
from yt_dlp.networking.common import _REQUEST_HANDLERS
from yt_dlp.utils._utils import _YDLLogger as FakeLogger


@pytest.fixture
def handler(request):
    RH_KEY = request.param
    if inspect.isclass(RH_KEY) and issubclass(RH_KEY, RequestHandler):
        handler = RH_KEY
    elif RH_KEY in _REQUEST_HANDLERS:
        handler = _REQUEST_HANDLERS[RH_KEY]
    else:
        pytest.skip(f'{RH_KEY} request handler is not available')

    class HandlerWrapper(handler):
        RH_KEY = handler.RH_KEY

        def __init__(self, *args, **kwargs):
            super().__init__(logger=FakeLogger, *args, **kwargs)

    return HandlerWrapper


@pytest.fixture(autouse=True)
def skip_handler(request, handler):
    if request.node.get_closest_marker('skip_handler'):
        args = request.node.get_closest_marker('skip_handler').args
        if args[0] == handler.RH_KEY:
            pytest.skip(args[1] if len(args) > 1 else '')


@pytest.fixture(autouse=True)
def skip_handler_if(request, handler):
    if request.node.get_closest_marker('skip_handler_if'):
        args = request.node.get_closest_marker('skip_handler_if').args
        if args[0] == handler.RH_KEY and args[1](request):
            pytest.skip(args[2] if len(args) > 2 else '')


def validate_and_send(rh, req):
    rh.validate(req)
    return rh.send(req)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "skip_handler(handler): skip test for the given handler",
    )
    config.addinivalue_line(
        "markers", "skip_handler_if(handler): skip test for the given handler if condition is true"
    )
