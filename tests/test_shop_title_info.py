import base64
from contextlib import ExitStack, nullcontext
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from flask import Flask
from PIL import Image
import requests
from werkzeug.security import generate_password_hash

from app import app as appmod
from app.db import db, User


TITLE_ID = '0100AAAABBBB0000'
INFO_URL = f'/api/shop/title-info/{TITLE_ID}'
SCREEN_URL = f'/api/shop/screenshot/{TITLE_ID}/0'


class ShopTitleInfoTests(unittest.TestCase):
    def setUp(self):
        # Dispatch the production views with real Basic auth and an isolated DB.
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        db.init_app(self.app)
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        db.create_all()
        self.addCleanup(db.drop_all)
        self.addCleanup(db.session.remove)
        self.user = User(user='fixture', password=generate_password_hash('fixture-password'),
                         shop_access=True, admin_access=False, frozen=False)
        db.session.add(self.user)
        db.session.commit()
        for rule in appmod.app.url_map.iter_rules():
            if rule.endpoint in ('shop_title_info_api', 'sphaira_screenshot_api'):
                self.app.add_url_rule(rule.rule, rule.endpoint, appmod.app.view_functions[rule.endpoint])
        self.client = self.app.test_client(use_cookies=False)
        self.shop = {'public': False}
        self.info = {'description': 'Example description', 'rating': 10,
                     'screenshots': ['https://example.invalid/screen.png']}
        self.stack = self.enterContext(ExitStack())
        for target, value in [
            ('app.app.app_settings', {'shop': self.shop}),
            ('app.app.current_user', SimpleNamespace(is_authenticated=False)),
        ]:
            self.stack.enter_context(patch(target, value))
        for target, value in [
            ('app.app._maybe_sync_request_settings', None),
            ('app.auth.load_settings', {'security': {'auth_ip_lockout_enabled': False}}),
            ('app.app.load_settings', {}),
            ('app.auth._log_login_event', None),
            ('app.app._content_filter_block_unrated', True),
            ('app.app.titles.titledb_session', nullcontext()),
        ]:
            self.stack.enter_context(patch(target, return_value=value))
        self.metadata = self.stack.enter_context(patch('app.app.titles.get_game_info', side_effect=lambda _: self.info))
        self.fetch = self.stack.enter_context(patch('app.sphaira.requests.get'))
        self.directory = self.enterContext(tempfile.TemporaryDirectory(dir='.tmp'))
        self.stack.enter_context(patch('app.app.CACHE_DIR', self.directory))

    def get(self, url, password='fixture-password', **kwargs):
        headers = {'User-Agent': 'CyberFoil/1.0'}
        if password is not None:
            credentials = base64.b64encode(f'fixture:{password}'.encode()).decode()
            headers['Authorization'] = 'Basic ' + credentials
        headers.update(kwargs.pop('headers', {}))
        return self.client.get(url, headers=headers, **kwargs)

    def image_download(self, size=(1600, 1200)):
        data = io.BytesIO()
        Image.new('RGB', size, (50, 100, 150)).save(data, format='PNG')
        self.fetch.return_value.__enter__.return_value.iter_content.return_value = [data.getvalue()]

    def test_metadata_with_shop_credentials_without_cookies(self):
        self.info['screenshots'] += ['', None, 'file:///fixture.png', '//example.invalid/second.png']
        response = self.get(INFO_URL.lower())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {
            'success': True, 'title_id': TITLE_ID, 'description': 'Example description',
            'screenshots': [SCREEN_URL, f'/api/shop/screenshot/{TITLE_ID}/4'],
        })
        self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
        self.assertNotIn('Set-Cookie', response.headers)
        self.metadata.assert_called_once_with(TITLE_ID)
        self.fetch.assert_not_called()

    def test_missing_or_bad_credentials_are_denied_before_metadata_or_download(self):
        for url in (INFO_URL, SCREEN_URL):
            for password in (None, 'wrong-password'):
                with self.subTest(url=url, password=password):
                    response = self.get(url, password=password)
                    self.assertIn('error', response.get_json())
        self.metadata.assert_not_called()
        self.fetch.assert_not_called()

    def test_shop_permission_and_frozen_accounts_are_denied(self):
        for attribute in ('shop_access', 'frozen'):
            setattr(self.user, attribute, attribute == 'frozen')
            db.session.commit()
            for url in (INFO_URL, SCREEN_URL):
                with self.subTest(attribute=attribute, url=url):
                    self.assertIn('error', self.get(url).get_json())
            setattr(self.user, attribute, attribute != 'frozen')
        self.metadata.assert_not_called()
        self.fetch.assert_not_called()

    def test_public_shop_allows_anonymous_requests(self):
        self.shop['public'] = True
        self.image_download()
        self.assertTrue(self.get(INFO_URL, password=None).get_json()['success'])
        response = self.get(SCREEN_URL, password=None)
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_basic_credentials_also_work_without_a_shop_user_agent(self):
        self.image_download()
        self.assertTrue(self.get(INFO_URL, headers={'User-Agent': 'ExampleClient'}).get_json()['success'])
        response = self.get(SCREEN_URL, headers={'User-Agent': 'ExampleClient'})
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_external_and_host_restrictions_match_icons(self):
        self.shop['external_tinfoil_only'] = True
        for url in (INFO_URL, SCREEN_URL):
            with self.subTest(url=url), patch.object(appmod, '_effective_remote_addr', return_value='203.0.113.10'), \
                    patch.object(appmod, '_is_private_ip', return_value=False):
                response = self.get(url, headers={'User-Agent': 'ExampleClient'},
                                    environ_overrides={'REMOTE_ADDR': '203.0.113.10'})
                self.assertEqual(response.status_code, 403)
                self.shop.update(host='localhost', hauth='fixture-hauth')
                response = self.get(url, base_url='https://localhost', headers={'Hauth': 'incorrect'})
                self.assertIn('error', response.get_json())
        self.metadata.assert_not_called()
        self.fetch.assert_not_called()

    def test_age_and_unrated_restrictions_apply_before_cached_images(self):
        self.user.max_rating = 13
        db.session.commit()
        self.image_download()
        response = self.get(SCREEN_URL)
        self.assertEqual(response.status_code, 200)
        response.close()
        self.fetch.reset_mock()
        for rating in (18, None, 'invalid'):
            self.info['rating'] = rating
            for url in (INFO_URL, SCREEN_URL):
                with self.subTest(rating=rating, url=url):
                    self.assertEqual(self.get(url).status_code, 403)
        self.fetch.assert_not_called()

    def test_missing_and_malformed_metadata(self):
        for info in ({}, {'description': None, 'screenshots': None},
                     {'description': 42, 'screenshots': 'https://example.invalid/screen.jpg'},
                     {'screenshots': {'0': 'https://example.invalid/screen.jpg'}}):
            self.info = info
            with self.subTest(info=info):
                self.assertEqual(self.get(INFO_URL).get_json(), {
                    'success': True, 'title_id': TITLE_ID, 'description': None, 'screenshots': [],
                })
                self.assertEqual(self.get(SCREEN_URL).status_code, 404)
        self.fetch.assert_not_called()

    def test_invalid_title_ids_and_indexes(self):
        for title_id in ('invalid', '0100AAAABBBB000G', '0100AAAABBBB00000'):
            self.assertEqual(self.get(f'/api/shop/title-info/{title_id}').status_code, 400)
            self.assertEqual(self.get(f'/api/shop/screenshot/{title_id}/0').status_code, 404)
        self.metadata.assert_not_called()
        for index in ('-1', '1', '999999999999999999999', 'invalid'):
            self.assertEqual(self.get(f'/api/shop/screenshot/{TITLE_ID}/{index}').status_code, 404)
        self.fetch.assert_not_called()

    def test_invalid_screenshot_sources_and_size(self):
        for source in ('', None, 'file:///fixture.jpg', 'https://[', '/static/fixture.jpg'):
            self.info['screenshots'] = [source]
            self.assertEqual(self.get(SCREEN_URL).status_code, 404)
        self.assertEqual(self.get(SCREEN_URL + '?size=invalid').status_code, 400)
        self.fetch.assert_not_called()

    def test_screenshot_retrieval_preserves_aspect_ratio_and_caches(self):
        self.image_download()
        for _ in range(2):
            response = self.get(SCREEN_URL)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, 'image/jpeg')
            self.assertEqual(response.headers['Cache-Control'], 'private, max-age=3600')
            with Image.open(io.BytesIO(response.data)) as image:
                self.assertEqual(image.size, (540, 405))
            response.close()
        self.fetch.assert_called_once_with('https://example.invalid/screen.png', stream=True, timeout=(5, 20))
        self.assertNotIn('auth', self.fetch.call_args.kwargs)
        response = self.get(SCREEN_URL, headers={'If-None-Match': response.headers['ETag']})
        self.assertEqual(response.status_code, 304)
        response.close()
        self.assertEqual(self.fetch.call_count, 1)

    def test_source_changes_and_size_variants_use_separate_cache_files(self):
        self.image_download()
        for url in (SCREEN_URL, SCREEN_URL + '?size=screen'):
            self.get(url).close()
        self.info['screenshots'][0] = '//example.invalid/new.png'
        self.get(SCREEN_URL).close()
        self.assertEqual(self.fetch.call_count, 3)
        self.assertEqual(len(list(Path(self.directory, 'screenshots').glob('*.jpg'))), 3)
        self.assertEqual(self.fetch.call_args.args[0], 'https://example.invalid/new.png')

    def test_failed_downloads_are_not_cached_and_can_retry(self):
        for error in (requests.Timeout('fixture timeout'), requests.HTTPError('fixture HTTP failure')):
            self.fetch.side_effect = error
            response = self.get(SCREEN_URL)
            self.assertEqual(response.status_code, 502)
            self.assertEqual(response.get_json()['error'], 'Screenshot is unavailable.')
        self.fetch.side_effect = None
        self.fetch.return_value.__enter__.return_value.iter_content.return_value = [b'invalid image']
        self.assertEqual(self.get(SCREEN_URL).status_code, 502)
        self.assertEqual(list(Path(self.directory).rglob('*.jpg')), [])
        self.image_download()
        response = self.get(SCREEN_URL)
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_metadata_failure_returns_service_unavailable(self):
        self.metadata.side_effect = OSError('fixture metadata failure')
        for url in (INFO_URL, SCREEN_URL):
            self.assertEqual(self.get(url).status_code, 503)
        self.fetch.assert_not_called()

    def test_existing_web_metadata_keeps_original_screenshot_urls(self):
        with self.app.test_request_context(f'/api/title-info/{TITLE_ID}'), \
                patch.object(appmod.titles, 'load_titledb'), patch.object(appmod.titles, 'release_titledb'):
            response = appmod.get_title_info_api.__wrapped__(TITLE_ID)
        self.assertEqual(response.get_json()['screenshots'], self.info['screenshots'])


if __name__ == '__main__':
    unittest.main()
