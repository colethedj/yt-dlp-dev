# flake8: noqa: F405
from urllib.request import *  # noqa: F403
from .. import compat_os_name
from ..compat_utils import passthrough_module
import sys

passthrough_module(__name__, 'urllib.request')
del passthrough_module


if compat_os_name == 'nt':
    # Workaround for https://github.com/python/cpython/issues/86793 for older python versions
    # This issue only occurs for the case where there is only
    # one proxy url for all protocols and if the proxy scheme is not http.
    # urllib will erroneously set http, https and ftp proxy types
    # to such proxy url with the proxy type scheme appended on with no checks.
    # See: https://github.com/python/cpython/blob/51f1ae5ceb0673316c4e4b0175384e892e33cc6e/Lib/urllib/request.py#L2693-L2698
    from urllib.request import getproxies_environment, _parse_proxy, getproxies_registry

    def getproxies_registry_patched():
        proxies = getproxies_registry()
        if (
            sys.version_info >= (3, 10, 5)  # https://docs.python.org/3.10/whatsnew/changelog.html#python-3-10-5-final
            or (3, 9, 13) <= sys.version_info < (3, 10,)  # https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-13-final
        ):
            return proxies

        # The erroneous branch will set all three of these
        proxy_schemes = {'http', 'https', 'ftp'}
        if set(proxies.keys()) != proxy_schemes and all(purl.startswith(f'{pk}://') for pk, purl in proxies.items()):
            return proxies

        for proxy_key, proxy_url in proxies.items():
            # Remove erroneously added proxy scheme and rebuild the proxy url
            proxy_type, user, password, hp = _parse_proxy(proxy_url[len(f'{proxy_key}://'):])
            # the existing proxy may or may not have a scheme. Use http as default.
            proxies[proxy_key] = (proxy_type or 'http') + '://'
            if user and password:
                proxies[proxy_key] += f'{user}:{password}@'
            proxies[proxy_key] += hp
        return proxies

    def getproxies():
        return getproxies_environment() or getproxies_registry_patched()




