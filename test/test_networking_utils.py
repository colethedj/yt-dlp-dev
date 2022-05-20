# Allow direct execution
import os
import sys
import unittest
from yt_dlp.networking.utils import select_proxy, MultiHTTPHeaderDict, HTTPHeaderDict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class TestNetworkingUtils(unittest.TestCase):

    def test_select_proxy(self):
        proxies = {
            'all': 'socks5://example.com',
            'http': 'http://example.com:1080',
        }

        self.assertEqual(select_proxy('https://example.com', proxies), proxies['all'])
        self.assertEqual(select_proxy('http://example.com', proxies), proxies['http'])

    def test_multi_header_dict(self):
        # TODO
        headers = MultiHTTPHeaderDict()
        headers.add_header('test', '1')
        headers.add_header('test', '2')
        self.assertEqual(list(headers.items()), [('test', '1'), ('test', '2')])

    def test_unique_header_dict(self):
        # TODO
        headers = HTTPHeaderDict()
        headers.add_header('test', '1')
        headers.add_header('test', '2')
        self.assertEqual(list(headers.items()), [('test', '2')])


if __name__ == '__main__':
    unittest.main()
