# Allow direct execution
import functools
import os
import subprocess
import sys
import unittest
from random import random

from yt_dlp.networking import UrllibRH, REQUEST_HANDLERS, UnsupportedRH, RequestsRH
from yt_dlp.networking.common import Request, RHManager, HEADRequest
from yt_dlp.utils import HTTPError, SSLError, TransportError, IncompleteRead
from yt_dlp.networking.utils import select_proxy
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test.helper import http_server_port, FakeYDL, is_download_test, get_params
from yt_dlp import YoutubeDL
from yt_dlp.compat import compat_http_server
import ssl
import threading

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class TestNetworkingUtils(unittest.TestCase):

    def test_select_proxy(self):
        proxies = {
            'all': 'socks5://example.com',
            'http': 'http://example.com:1080',
        }

        self.assertEqual(select_proxy('https://example.com', proxies), proxies['all'])
        self.assertEqual(select_proxy('http://example.com', proxies), proxies['http'])


if __name__ == '__main__':
    unittest.main()