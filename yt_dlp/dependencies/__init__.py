# flake8: noqa: F401
"""Imports all optional dependencies for the project.

Internal attributes may be added to the modules to provide additional information:

- _yt_dlp__is_supported_version: bool representing whether the version of the dependency is supported
- _yt_dlp__version_tuple: tuple representing the version of the dependency
- _yt_dlp__version: str representing the version of the dependency
- _yt_dlp__identifier: str representing the module name. useful if the module uses an ambiguous namespace

"""
import collections as _collections
import dataclasses as _dataclasses
import re as _re
from typing import Any as _Any


def _set_version(module: _Any, version: str):
    module._yt_dlp__version = version


def _set_version_tuple(module: _Any, version_tuple: tuple):
    module._yt_dlp__version_tuple = version_tuple


def _set_supported_version(module: _Any, supported: bool):
    module._yt_dlp__is_supported_version = supported


def _get_version(module):
    return str(next(filter(None, (
        getattr(module, attr, None)
        for attr in ('_yt_dlp__version', '__version__', 'version_string', 'version')
    )), None))


def _get_version_tuple(module):
    version_tuple = getattr(module, '_yt_dlp__version_tuple', None)
    if version_tuple:
        return version_tuple

    version = _get_version(module)
    if version and _re.match(r'^[\d.]+$', version):
        # Parse version like '1.2.3' into tuple (1, 2, 3)
        # If version is not in the correct format, return None
        return tuple(map(int, version.split('.')))


try:
    import brotlicffi as brotli
except ImportError:
    try:
        import brotli
    except ImportError:
        brotli = None


try:
    import certifi
except ImportError:
    certifi = None
else:
    from os.path import exists as _path_exists

    # The certificate may not be bundled in executable
    if not _path_exists(certifi.where()):
        certifi = None


try:
    import mutagen
except ImportError:
    mutagen = None


secretstorage = None
try:
    import secretstorage
    _SECRETSTORAGE_UNAVAILABLE_REASON = None
except ImportError:
    _SECRETSTORAGE_UNAVAILABLE_REASON = (
        'as the `secretstorage` module is not installed. '
        'Please install by running `python3 -m pip install secretstorage`')
except Exception as _err:
    _SECRETSTORAGE_UNAVAILABLE_REASON = f'as the `secretstorage` module could not be initialized. {_err}'


try:
    import sqlite3
    # We need to get the underlying `sqlite` version, see https://github.com/yt-dlp/yt-dlp/issues/8152
    _set_version(sqlite3, sqlite3.sqlite_version)
except ImportError:
    # although sqlite3 is part of the standard library, it is possible to compile Python without
    # sqlite support. See: https://github.com/yt-dlp/yt-dlp/issues/544
    sqlite3 = None


try:
    import websockets
    _set_version(websockets, websockets.version.version)
    _set_supported_version(websockets, _get_version_tuple(websockets) >= (12, 0))
except ImportError:
    websockets = None

try:
    import urllib3
    _set_supported_version(urllib3, _get_version_tuple(urllib3) >= (1, 26, 17))
except ImportError:
    urllib3 = None

try:
    import requests
    _set_supported_version(requests, _get_version_tuple(requests) >= (2, 32, 2))
except ImportError:
    requests = None


try:
    import xattr  # xattr or pyxattr
except ImportError:
    xattr = None
else:
    if hasattr(xattr, 'set'):  # pyxattr
        xattr._yt_dlp__identifier = 'pyxattr'

try:
    import curl_cffi
    _curl_cffi_version_tuple = _get_version_tuple(curl_cffi)
    _set_supported_version(curl_cffi, _curl_cffi_version_tuple == (0, 5, 10) or ((0, 7, 0) <= _curl_cffi_version_tuple < (0, 8, 0)))
except ImportError:
    curl_cffi = None

from . import Cryptodome

all_dependencies = {k: v for k, v in globals().items() if not k.startswith('_')}
available_dependencies = {k: v for k, v in all_dependencies.items() if v}

# Deprecated
Cryptodome_AES = Cryptodome.AES


@_dataclasses.dataclass
class _Package:
    name: str
    version: str
    version_tuple: tuple
    supported: bool

    def __str__(self):
        s = self.name
        if self.version is not None:
            s += f'-{self.version}'
        if not self.supported:
            s += ' (unsupported)'
        return s


def get_package_info(module):
    return _Package(
        name=getattr(module, '_yt_dlp__identifier', module and module.__name__),
        version=_get_version(module),
        version_tuple=_get_version_tuple(module),
        supported=getattr(module, '_yt_dlp__is_supported_version', bool(module)))


__all__ = [
    'all_dependencies',
    'available_dependencies',
    'get_package_info',
    *all_dependencies.keys(),
]
