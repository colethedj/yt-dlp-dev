# flake8: noqa: F405
from urllib.request import *  # noqa: F403
from .. import compat_os_name
from ..compat_utils import passthrough_module
import re

passthrough_module(__name__, 'urllib.request')
del passthrough_module


if compat_os_name == 'nt':
    # TODO: limit python versions
    # Workaround for https://github.com/python/cpython/issues/86793 for older python versions
    from urllib.request import getproxies_environment, _parse_proxy, getproxies_registry

    def getproxies_registry_patched():
        proxies = getproxies_registry()
        new_proxies = proxies.copy()
        for proxy_key, proxy_url in proxies.items():
            proxy_type, user, password, hp = _parse_proxy(proxy_url)
            if proxy_key != proxy_type:
                return proxies
            new_proxies[proxy_key] = 'http://'
            if user and password:
                new_proxies[proxy_key] += f'{user}:{password}@'
            new_proxies[proxy_key] += hp
        return new_proxies

    def getproxies():
        return getproxies_environment() or getproxies_registry_patched()




