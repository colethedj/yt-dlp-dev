# Allow direct execution
import os
import sys
import unittest
from yt_dlp.networking.utils import select_proxy, MultiHTTPHeaderDict, HTTPHeaderDict, NewHTTPHeaderDict, \
    AnotherHTTPHeaderDict

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
        headers = AnotherHTTPHeaderDict()
        headers['test-again'] = 1
        self.assertEqual(list(headers.items()), [('Test-Again', '1')])
        headers['Test-again'] = '2'
        self.assertEqual(list(headers.items()), [('Test-Again', '2')])
        self.assertTrue('test-aGain' in headers)
        self.assertEqual(str(headers), str(dict(headers)))
        self.assertEqual(repr(headers), str(dict(headers)))
        headers.update({'X-bob': 'again'})
        self.assertEqual(list(headers.items()), [('Test-Again', '2'), ('X-Bob', 'again')])
        self.assertEqual(dict(headers), {'Test-Again': '2', 'X-Bob': 'again'})
        self.assertEqual(len(headers), 2)
        self.assertEqual(headers.copy(), headers)
        headers2 = AnotherHTTPHeaderDict(**headers, **{'X-bob': 'yes'})
        self.assertEqual(list(headers2.items()), [('Test-Again', '2'), ('X-Bob', 'yes')])
        self.assertEqual(len(headers2), 2)
        headers2.clear()
        self.assertEqual(len(headers2), 0)


if __name__ == '__main__':
    unittest.main()
