import os
import sys
import warnings
import xml.etree.ElementTree as etree

from . import re
from ._deprecated import *  # noqa: F401, F403
from .compat_utils import passthrough_module

from urllib.request import getproxies, getproxies_environment

# XXX: Implement this the same way as other DeprecationWarnings without circular import
try:
    passthrough_module(__name__, '._legacy', callback=lambda attr: warnings.warn(
        DeprecationWarning(f'{__name__}.{attr} is deprecated'), stacklevel=2))
    HAS_LEGACY = True
except ModuleNotFoundError:
    # Keep working even without _legacy module
    HAS_LEGACY = False
del passthrough_module


# HTMLParseError has been deprecated in Python 3.3 and removed in
# Python 3.5. Introducing dummy exception for Python >3.5 for compatible
# and uniform cross-version exception handling
class compat_HTMLParseError(Exception):
    pass


class _TreeBuilder(etree.TreeBuilder):
    def doctype(self, name, pubid, system):
        pass


def compat_etree_fromstring(text):
    return etree.XML(text, parser=etree.XMLParser(target=_TreeBuilder()))


compat_os_name = os._name if os.name == 'java' else os.name


if compat_os_name == 'nt':
    def compat_shlex_quote(s):
        return s if re.match(r'^[-_\w./]+$', s) else '"%s"' % s.replace('"', '\\"')
else:
    from shlex import quote as compat_shlex_quote  # noqa: F401


def compat_ord(c):
    return c if isinstance(c, int) else ord(c)


if compat_os_name == 'nt' and sys.version_info < (3, 8):
    # os.path.realpath on Windows does not follow symbolic links
    # prior to Python 3.8 (see https://bugs.python.org/issue9949)
    def compat_realpath(path):
        while os.path.islink(path):
            path = os.path.abspath(os.readlink(path))
        return path
else:
    compat_realpath = os.path.realpath


# Python 3.8+ does not honor %HOME% on windows, but this breaks compatibility with youtube-dl
# See https://github.com/yt-dlp/yt-dlp/issues/792
# https://docs.python.org/3/library/os.path.html#os.path.expanduser
if compat_os_name in ('nt', 'ce'):
    def compat_expanduser(path):
        HOME = os.environ.get('HOME')
        if not HOME:
            return os.path.expanduser(path)
        elif not path.startswith('~'):
            return path
        i = path.replace('\\', '/', 1).find('/')  # ~user
        if i < 0:
            i = len(path)
        userhome = os.path.join(os.path.dirname(HOME), path[1:i]) if i > 1 else HOME
        return userhome + path[i:]
else:
    compat_expanduser = os.path.expanduser

if compat_os_name == 'nt':
    """
    Code from https://github.com/python/cpython/blob/main/Lib/urllib/request.py
    https://github.com/python/cpython/pull/26307
    """
    def getproxies_registry():
        """Return a dictionary of scheme -> proxy server URL mappings.
        Win32 uses the registry to store proxies.
        """
        proxies = {}
        try:
            import winreg
        except ImportError:
            # Std module, so should be around - but you never know!
            return proxies
        try:
            internetSettings = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                              r'Software\Microsoft\Windows\CurrentVersion\Internet Settings')
            proxyEnable = winreg.QueryValueEx(internetSettings,
                                              'ProxyEnable')[0]
            if proxyEnable:
                # Returned as Unicode but problems if not converted to ASCII
                proxyServer = str(winreg.QueryValueEx(internetSettings,
                                                      'ProxyServer')[0])
                if '=' not in proxyServer and ';' not in proxyServer:
                    # Use one setting for all protocols.
                    proxyServer = 'http={0};https={0};ftp={0}'.format(proxyServer)
                for p in proxyServer.split(';'):
                    protocol, address = p.split('=', 1)
                    # See if address has a type:// prefix
                    if not re.match('(?:[^/:]+)://', address):
                        # Add type:// prefix to address without specifying type
                        if protocol in ('http', 'https', 'ftp'):
                            # The default proxy type of Windows is HTTP
                            address = 'http://' + address
                        elif protocol == 'socks':
                            address = 'socks://' + address
                    proxies[protocol] = address
                # Use SOCKS proxy for HTTP(S) protocols
                if proxies.get('socks'):
                    # The default SOCKS proxy type of Windows is SOCKS4
                    address = re.sub(r'^socks://', 'socks4://', proxies['socks'])
                    proxies['http'] = proxies.get('http') or address
                    proxies['https'] = proxies.get('https') or address
            internetSettings.Close()
        except (OSError, ValueError, TypeError):
            # Either registry key not found etc, or the value in an
            # unexpected format.
            # proxies already set up to be empty so nothing to do
            pass
        return proxies

    def getproxies():
        return getproxies_environment() or getproxies_registry()


compat_getproxies = getproxies
