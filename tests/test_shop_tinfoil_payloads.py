import copy
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch


_IMPORT_ERROR = None
flask_app = None
index = None
shop_sections_api = None
shop_sections_cache = None
shop_sections_cache_lock = None
tinfoil_access = None
try:
    from app.app import app as flask_app
    from app.app import index, shop_sections_api, shop_sections_cache, shop_sections_cache_lock, tinfoil_access
except ModuleNotFoundError as exc:
    _IMPORT_ERROR = exc


class ShopTinfoilPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _IMPORT_ERROR is not None:
            raise unittest.SkipTest(f"Missing dependency for shop payload tests: {_IMPORT_ERROR}")

    def setUp(self):
        self.base_shop_settings = {
            'public': True,
            'encrypt': True,
            'tinfoil_only_mode': False,
            'motd': 'Example MOTD',
            'public_key': '',
            'external_tinfoil_only': False,
        }
        with shop_sections_cache_lock:
            self.original_sections_cache = copy.deepcopy(shop_sections_cache)

    def tearDown(self):
        with shop_sections_cache_lock:
            shop_sections_cache.clear()
            shop_sections_cache.update(copy.deepcopy(self.original_sections_cache))

    def test_index_returns_html_for_browser_in_tinfoil_only_mode(self):
        shop_settings = dict(self.base_shop_settings)
        shop_settings['tinfoil_only_mode'] = True

        with flask_app.test_request_context(
            '/',
            method='GET',
            headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'},
        ):
            with (
                patch('app.app._maybe_sync_request_settings', return_value=None),
                patch('app.app.app_settings', {'shop': shop_settings}),
                patch('app.app.access_shop', return_value='HTML PAGE'),
            ):
                response = index()

        self.assertEqual(response, 'HTML PAGE')

    def test_index_returns_tinfoil_payload_for_non_browser_in_tinfoil_only_mode(self):
        shop_settings = dict(self.base_shop_settings)
        shop_settings['tinfoil_only_mode'] = True

        with flask_app.test_request_context('/', method='GET', headers={'User-Agent': 'curl/8.0'}):
            with (
                patch('app.app._maybe_sync_request_settings', return_value=None),
                patch('app.app.app_settings', {'shop': shop_settings}),
                patch('app.app._get_cached_shop_files', return_value=[{'url': '/api/get_game/1#example.nsp', 'size': 1}]),
            ):
                response = index()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/octet-stream')
        self.assertTrue(response.get_data().startswith(b'TINFOIL'))

    def test_shop_sections_returns_tinfoil_payload_when_encryption_enabled(self):
        shop_settings = dict(self.base_shop_settings)
        with shop_sections_cache_lock:
            shop_sections_cache.clear()
            shop_sections_cache.update({
                'limit': 50,
                'timestamp': time.time(),
                'state_token': 'test-token',
                'payload': {
                    'rotation_key': 'test-day',
                    'sections': [
                        {'id': 'all', 'title': 'All', 'items': []},
                    ]
                },
                'encrypted': {},
            })

        with flask_app.test_request_context('/api/shop/sections', method='GET', headers={'User-Agent': 'Tinfoil/1.0'}):
            with (
                patch('app.app._maybe_sync_request_settings', return_value=None),
                patch('app.app.app_settings', {'shop': shop_settings}),
                patch('app.app._get_titledb_aware_state_token', return_value='test-token'),
                patch('app.app._recommendation_rotation_key', return_value='test-day'),
            ):
                response = shop_sections_api()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/octet-stream')
        self.assertTrue(response.get_data().startswith(b'TINFOIL'))

    def test_frozen_account_uses_error_field_in_shop_payload(self):
        shop_settings = dict(self.base_shop_settings)
        shop_settings['public'] = False
        shop_settings['encrypt'] = False
        frozen_user = SimpleNamespace(frozen=True, frozen_message='Account frozen by admin.')
        fake_user_model = SimpleNamespace(
            query=SimpleNamespace(
                filter_by=lambda **kwargs: SimpleNamespace(first=lambda: frozen_user)
            )
        )

        @tinfoil_access
        def protected_endpoint():
            return 'unreachable'

        with flask_app.test_request_context(
            '/',
            method='GET',
            headers={
                'Authorization': 'Basic ZXhhbXBsZS11c2VyOmV4YW1wbGUtcGFzc3dvcmQ=',
                'User-Agent': 'Tinfoil/1.0',
            },
        ):
            with (
                patch('app.app._maybe_sync_request_settings', return_value=None),
                patch('app.app.app_settings', {'shop': shop_settings}),
                patch('app.app.basic_auth', return_value=(False, 'Account frozen by admin.', False)),
                patch('app.app.User', fake_user_model),
            ):
                response = protected_endpoint()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {
            'error': 'Account frozen by admin.',
            'files': [{'url': '/api/frozen/notice#frozen.txt', 'size': 1}],
        })


if __name__ == '__main__':
    unittest.main()
