# flake8: noqa: F405
from urllib.request import *  # noqa: F403
from .. import compat_os_name
from ..compat_utils import passthrough_module
import sys

passthrough_module(__name__, 'urllib.request')
del passthrough_module


if compat_os_name == 'nt':
    # Workaround for an issue on older python versions where proxies are extracted from Windows registry erroneously. [1]
    # If the https proxy in the registry does not have a scheme, urllib will incorrectly add https:// to it. [2]
    # It is unlikely that the user has set it to actually be https,
    # so we should be fine to safely downgrade it to http on these affected versions to avoid issues.
    # 1: https://github.com/python/cpython/issues/86793
    # 2: https://github.com/python/cpython/blob/51f1ae5ceb0673316c4e4b0175384e892e33cc6e/Lib/urllib/request.py#L2683-L2698
    from urllib.request import getproxies_environment, _parse_proxy, getproxies_registry

    def getproxies_registry_patched():
        proxies = getproxies_registry()
        if (
            sys.version_info >= (3, 10, 5)  # https://docs.python.org/3.10/whatsnew/changelog.html#python-3-10-5-final
            or (3, 9, 13) <= sys.version_info < (3, 10,)  # https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-13-final
        ):
            return proxies

        if 'https' in proxies and proxies['https'].startswith(f'https://'):
            proxies['https'] = 'http' + proxies['https'][5:]  # Downgrade https proxy to http

        return proxies

    def getproxies():
        return getproxies_environment() or getproxies_registry_patched()




