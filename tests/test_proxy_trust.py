import unittest

from flask import Flask

from app.auth import _effective_client_ip


class ProxyTrustTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.settings = {
            'security': {
                'trust_proxy_headers': True,
                'trusted_proxies': ['172.16.0.0/12'],
            }
        }

    def test_effective_client_ip_trusts_xff_for_trusted_ipv4_proxy(self):
        with self.app.test_request_context(
            '/',
            environ_base={'REMOTE_ADDR': '172.20.0.10'},
            headers={'X-Forwarded-For': '203.0.113.42, 172.20.0.10'},
        ):
            self.assertEqual(_effective_client_ip(self.settings), '203.0.113.42')

    def test_effective_client_ip_trusts_xff_for_ipv4_mapped_ipv6_proxy(self):
        with self.app.test_request_context(
            '/',
            environ_base={'REMOTE_ADDR': '::ffff:172.20.0.10'},
            headers={'X-Forwarded-For': '203.0.113.42, 172.20.0.10'},
        ):
            self.assertEqual(_effective_client_ip(self.settings), '203.0.113.42')

    def test_effective_client_ip_ignores_xff_for_untrusted_proxy(self):
        with self.app.test_request_context(
            '/',
            environ_base={'REMOTE_ADDR': '10.0.0.10'},
            headers={'X-Forwarded-For': '203.0.113.42, 10.0.0.10'},
        ):
            self.assertEqual(_effective_client_ip(self.settings), '10.0.0.10')


if __name__ == '__main__':
    unittest.main()
