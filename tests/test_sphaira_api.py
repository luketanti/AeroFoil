import base64
import io
from pathlib import Path
import tempfile
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask
from PIL import Image

from app import app as appmod
from app.db import db, Apps, Files, Libraries, Titles
from app.sphaira import Catalogue, execute, cached_screenshot, screenshot_source


BASE_QUERY = '''query($page:Int!,$pageSize:Int!){apps(owned:true,appType:[BASE],groupByAppId:true,orderBy:{field:NAME,direction:ASC},page:$page,pageSize:$pageSize){total items{appId displayVersion latestOwnedVersion{displayVersion} titledb{name publisher icon(size:THUMB){url local} banner(size:THUMB){url local}}}}}'''
UPDATES_QUERY = '''query($page:Int!,$pageSize:Int!,$titleIds:[String!]){apps(owned:true,appType:[UPDATE],groupByAppId:true,filter:{titleId:{in:$titleIds}},page:$page,pageSize:$pageSize){total items{appId titleId appVersion}}}'''
TITLE_QUERY = '''query($id:ID!){title(titleId:$id){name publisher intro description releaseDate category numberOfPlayers size rating region banner(size:CLIENT){url local} fullBanner:banner(size:SCREEN){url local} availableVersions{version releaseDate} screenshots(size:CLIENT){url local} full:screenshots(size:SCREEN){url local} base:apps(owned:true,appType:[BASE]){displayVersion downloadSize downloadUrl downloadExtension latestOwnedVersion{version displayVersion}} updates:apps(owned:true,appType:[UPDATE]){appVersion displayVersion downloadUrl downloadExtension} dlc:apps(owned:true,appType:[DLC]){appId appVersion downloadUrl downloadExtension titledb{name intro banner(size:THUMB){url local}}}}}'''


class SphairaCatalogueTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        db.init_app(self.app)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        library = Libraries(path='X:/fixture-root')
        self.title_id = '0100AAAABBBB0000'
        self.other_id = '0100CCCCDDDD0000'
        title = Titles(title_id=self.title_id)
        other = Titles(title_id=self.other_id)
        db.session.add_all([library, title, other])
        db.session.flush()
        def add(parent, app_id, kind, version, file_id):
            file = Files(id=file_id, library=library, filepath=f'X:/fixture-root/example-{file_id}.nsp',
                         filename=f'example-{file_id}.nsp', extension='nsp', size=5_000_000_000)
            row = Apps(title=parent, app_id=app_id, app_type=kind, app_version=str(version), owned=True)
            row.files.append(file)
            db.session.add(row)
            return row
        add(title, self.title_id, 'BASE', 0, 1)
        add(title, '0100AAAABBBB0800', 'UPDATE', 65536, 2)
        add(title, '0100AAAABBBB0800', 'UPDATE', 131072, 3)
        add(title, '0100AAAABBBB1001', 'DLC', 0, 4)
        add(other, self.other_id, 'BASE', 0, 5)
        db.session.add(Apps(title=title, app_id='0100AAAABBBB1002', app_type='DLC', app_version='0', owned=False))
        db.session.commit()
        self.metadata = {
            self.title_id: {'name': 'Example Title', 'publisher': 'Example Publisher', 'rating': 10,
                            'iconUrl': 'https://example.invalid/icon.jpg', 'bannerUrl': 'https://example.invalid/banner.jpg',
                            'screenshots': ['https://example.invalid/screen.jpg'], 'category': 'Puzzle'},
            self.other_id: {'name': 'Another Example', 'rating': 18},
            '0100AAAABBBB1001': {'name': 'Example Add-on', 'intro': 'Example DLC description'},
        }
        self.info_patch = patch('app.sphaira.titles.get_game_info', side_effect=lambda tid: self.metadata.get(tid, {}))
        self.info_patch.start()
        self.index_patch = patch('app.sphaira.titles._titles_index_ready', False)
        self.index_patch.start()
        self.versions_patch = patch('app.sphaira.titles.get_all_existing_versions', return_value=[{'version': 131072, 'release_date': '2026-01-01'}])
        self.versions_patch.start()

    def tearDown(self):
        self.versions_patch.stop()
        self.index_patch.stop()
        self.info_patch.stop()
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def run_query(self, query, variables=None, cap=None, blocked=None):
        catalog = Catalogue(cap, True, appmod._title_allowed, lambda fid, *_: fid in (blocked or []))
        return execute({'query': query, 'variables': variables}, catalog)

    def test_native_base_query_paginates_and_sorts(self):
        result = self.run_query(BASE_QUERY, {'page': 2, 'pageSize': 1})
        self.assertNotIn('errors', result)
        self.assertEqual(result['data']['apps']['total'], 2)
        item = result['data']['apps']['items'][0]
        self.assertEqual(item['appId'], self.title_id)
        self.assertEqual(item['titledb']['icon'], {'url': f'/api/shop/icon/{self.title_id}', 'local': True})

    def test_updates_group_to_highest_owned_version(self):
        result = self.run_query(UPDATES_QUERY, {'page': 1, 'pageSize': 1000, 'titleIds': [self.title_id]})
        self.assertNotIn('errors', result)
        self.assertEqual(result['data']['apps']['total'], 1)
        self.assertEqual(result['data']['apps']['items'][0]['appVersion'], 131072)

    def test_null_pagination_uses_defaults_and_zero_clamps(self):
        result = self.run_query('{apps(owned:true,appType:BASE,page:null,pageSize:null){total items{appId}}}')
        self.assertNotIn('errors', result)
        self.assertEqual(len(result['data']['apps']['items']), 2)
        result = self.run_query('{apps(owned:true,appType:BASE,page:0,pageSize:0){total items{appId}}}')
        self.assertNotIn('errors', result)
        self.assertEqual(result['data']['apps']['total'], 2)
        self.assertEqual(len(result['data']['apps']['items']), 1)

    def test_native_details_aliases_and_large_download_size(self):
        result = self.run_query(TITLE_QUERY, {'id': self.title_id})
        self.assertNotIn('errors', result)
        title = result['data']['title']
        self.assertEqual(title['base'][0]['downloadSize'], 5_000_000_000)
        self.assertEqual(title['base'][0]['downloadUrl'], '/api/get_game/1')
        self.assertEqual(title['base'][0]['downloadExtension'], 'nsp')
        self.assertEqual(title['base'][0]['latestOwnedVersion']['version'], 131072)
        self.assertEqual(len(title['updates']), 2)
        self.assertEqual(len(title['dlc']), 1)
        self.assertEqual(title['dlc'][0]['titledb']['name'], 'Example Add-on')
        self.assertEqual(title['fullBanner'], title['banner'])
        self.assertEqual(title['screenshots'], [{'url': f'/api/shop/screenshot/{self.title_id}/0?size=client', 'local': True}])
        self.assertEqual(title['full'], [{'url': f'/api/shop/screenshot/{self.title_id}/0?size=screen', 'local': True}])

    def test_screenshot_urls_normalize_protocol_relative_sources(self):
        self.metadata[self.title_id]['screenshots'] = ['', '//example.invalid/screen.jpg', '/static/fixture.jpg']
        result = self.run_query(TITLE_QUERY, {'id': self.title_id})
        self.assertNotIn('errors', result)
        images = result['data']['title']['screenshots']
        self.assertEqual(images[0]['url'], f'/api/shop/screenshot/{self.title_id}/1?size=client')
        self.assertEqual(images[1], {'url': '/static/fixture.jpg', 'local': True})

    def test_category_filters_and_search(self):
        query = '''query($ids:[String!],$excluded:[String!]){apps(owned:true,appType:[DLC],groupByAppId:true,filter:{titleId:{in:$ids},appId:{notIn:$excluded}}){total items{appId downloadUrl}}}'''
        self.assertEqual(self.run_query(query, {'ids': [self.title_id], 'excluded': ['0100AAAABBBB1001']})['data']['apps']['total'], 0)
        query = '''query($text:String){apps(owned:true,appType:[BASE],search:$text){total items{appId}}}'''
        result = self.run_query(query, {'text': 'example title'})
        self.assertEqual(result['data']['apps']['total'], 1)
        query = '''query($ids:[String!]){apps(owned:true,appType:[BASE],filter:{appId:{notIn:$ids}}){total items{appId}}}'''
        self.assertEqual(self.run_query(query, {'ids': [self.title_id]})['data']['apps']['items'][0]['appId'], self.other_id)

    def test_age_limits_apply_to_pages_details_and_bundles(self):
        result = self.run_query(BASE_QUERY, {'page': 1, 'pageSize': 10}, cap=13)
        self.assertEqual(result['data']['apps']['total'], 1)
        self.assertIsNone(self.run_query(TITLE_QUERY, {'id': self.other_id}, cap=13)['data']['title'])
        result = self.run_query(BASE_QUERY, {'page': 1, 'pageSize': 10}, cap=13, blocked=[1])
        self.assertEqual(result['data']['apps']['total'], 0)
        self.metadata[self.title_id]['rating'] = None
        self.assertEqual(self.run_query(BASE_QUERY, {'page': 1, 'pageSize': 10}, cap=13)['data']['apps']['total'], 0)

    def test_validation_aliases_fragments_and_read_only_schema(self):
        result = self.run_query('query Named { page:apps(owned:true,appType:BASE){items{...Card}} } fragment Card on App { appId }')
        self.assertNotIn('errors', result)
        for payload in (None, {}, {'query': '{'}, {'query': '{apps{unknown}}'},
                        {'query': '{apps{total}}', 'variables': []}, {'query': 'mutation { deleteFile(id:1) }'}):
            with self.subTest(payload=payload):
                self.assertIn('errors', execute(payload, None))

    def test_depth_limit_and_operation_selection(self):
        query = '{apps{items{' + 'title{apps{' * 20 + 'appId' + '}}' * 20 + '}}}'
        self.assertIn('errors', self.run_query(query))
        result = execute({'query': 'query A {apps{total}} query B {apps{total}}', 'operationName': 'B'},
                         Catalogue(None, True, appmod._title_allowed, lambda *_: False))
        self.assertNotIn('errors', result)


class SphairaRouteTests(unittest.TestCase):
    def setUp(self):
        self.shop = {'public': True, 'discovery_name': 'Example Server', 'motd': 'Example MOTD'}
        self.settings = patch.object(appmod, 'app_settings', {'shop': self.shop})
        self.settings.start()
        self.sync = patch.object(appmod, '_maybe_sync_request_settings')
        self.sync.start()
        self.user = patch.object(appmod, 'current_user', SimpleNamespace(is_authenticated=False))
        self.user.start()

    def tearDown(self):
        self.user.stop()
        self.sync.stop()
        self.settings.stop()

    def test_handshake_protocol_identity_and_supported_features(self):
        with appmod.app.test_request_context('/', method='OPTIONS'), patch('app.discovery._server_uid', return_value='fixture-id'), patch.object(appmod, '_render_motd_template', return_value='Example MOTD'):
            result = appmod.index().get_json()
        self.assertEqual(result['uid'], 'fixture-id')
        self.assertEqual(result['name'], 'Example Server')
        self.assertEqual(result['protocol_version'], 1)
        self.assertTrue(result['features']['shop'])
        self.assertFalse(result['features']['save_backup'])

    def test_private_and_frozen_credentials_return_json_refusals(self):
        self.shop['public'] = False
        credentials = base64.b64encode(b'fixture:password').decode()
        for path, handler, method in [('/', appmod.index, 'OPTIONS'), ('/api/graphql', appmod.sphaira_graphql_api, 'POST')]:
            with appmod.app.test_request_context(path, method=method, headers={'Authorization': 'Basic ' + credentials}), patch.object(appmod, 'basic_auth', return_value=(False, 'Account is frozen.', False)):
                response, status = handler()
                self.assertEqual(status, 401)
                self.assertEqual(response.get_json()['error'], 'Account is frozen.')

    def test_public_shop_still_validates_supplied_credentials(self):
        credentials = base64.b64encode(b'fixture:wrong').decode()
        with appmod.app.test_request_context('/', method='OPTIONS', headers={'Authorization': 'Basic ' + credentials}), patch.object(appmod, 'basic_auth', return_value=(False, 'Incorrect password.', False)):
            self.assertEqual(appmod.index()[1], 401)

    def test_external_restriction_and_session_permissions(self):
        self.shop['external_tinfoil_only'] = True
        with appmod.app.test_request_context('/', method='OPTIONS'), patch.object(appmod, '_effective_remote_addr', return_value='203.0.113.10'), patch.object(appmod, '_is_private_ip', return_value=False):
            self.assertEqual(appmod.index()[1], 403)
        self.shop['external_tinfoil_only'] = False
        with appmod.app.test_request_context('/api/graphql', method='POST'), patch.object(appmod, 'current_user', SimpleNamespace(is_authenticated=True, frozen=False, has_access=lambda _: False)):
            self.assertEqual(appmod.sphaira_graphql_api()[1], 403)

    def test_graphql_route_returns_envelope(self):
        with appmod.app.test_request_context('/api/graphql', method='POST', json={'query': '{apps{total}}'}), patch.object(appmod, '_user_rating_cap', return_value=(None, True)), patch('app.sphaira.Catalogue.apps', return_value={'total': 0, 'items': []}), patch.object(appmod.titles, 'titledb_session', return_value=nullcontext()):
            self.assertEqual(appmod.sphaira_graphql_api().get_json(), {'data': {'apps': {'total': 0}}})

    def test_frozen_session_handshake_is_json_before_route_dispatch(self):
        with appmod.app.test_request_context('/', method='OPTIONS'), patch.object(appmod, '_is_shop_client_request', return_value=False), patch.object(appmod, 'current_user', SimpleNamespace(is_authenticated=True, frozen=True, frozen_message='Example frozen notice')):
            response, status = appmod._block_frozen_web_ui()
        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Example frozen notice')

    def test_screenshot_route_checks_access_and_rating_before_fetch(self):
        with appmod.app.test_request_context('/api/shop/screenshot/0100AAAABBBB0000/0'), patch.object(appmod, '_user_rating_cap', return_value=(13, True)), patch.object(appmod.titles, 'titledb_session', return_value=nullcontext()), patch.object(appmod.titles, 'get_game_info', return_value={'rating': 18, 'screenshots': ['https://example.invalid/image.jpg']}), patch('app.sphaira.cached_screenshot') as fetch:
            self.assertEqual(appmod.sphaira_screenshot_api('0100AAAABBBB0000', 0).status_code, 403)
            fetch.assert_not_called()
        self.shop['public'] = False
        with appmod.app.test_request_context('/api/shop/screenshot/0100AAAABBBB0000/0'), patch.object(appmod, 'basic_auth', return_value=(False, 'Shop requires authentication.', False)), patch('app.sphaira.cached_screenshot') as fetch:
            self.assertEqual(appmod.sphaira_screenshot_api('0100AAAABBBB0000', 0)[1], 401)
            fetch.assert_not_called()

    def test_screenshot_route_serves_jpeg_and_validates_position(self):
        info = {'rating': 10, 'screenshots': ['https://example.invalid/screen.jpg']}
        with tempfile.TemporaryDirectory(dir='.tmp') as directory:
            path = Path(directory, 'fixture.jpg').resolve()
            Image.new('RGB', (32, 18)).save(path)
            with appmod.app.test_request_context('/api/shop/screenshot/0100AAAABBBB0000/0?size=screen'), patch.object(appmod, '_user_rating_cap', return_value=(None, True)), patch.object(appmod.titles, 'titledb_session', return_value=nullcontext()), patch.object(appmod.titles, 'get_game_info', return_value=info), patch('app.sphaira.cached_screenshot', return_value=str(path)) as fetch:
                response = appmod.sphaira_screenshot_api('0100AAAABBBB0000', 0)
                self.assertEqual(response.mimetype, 'image/jpeg')
                self.assertEqual(response.headers['Cache-Control'], 'private, max-age=3600')
                self.assertEqual(fetch.call_args.args[-1], 'SCREEN')
                response.close()
            with appmod.app.test_request_context('/api/shop/screenshot/0100AAAABBBB0000/1'), patch.object(appmod, '_user_rating_cap', return_value=(None, True)), patch.object(appmod.titles, 'titledb_session', return_value=nullcontext()), patch.object(appmod.titles, 'get_game_info', return_value=info), patch('app.sphaira.cached_screenshot') as fetch:
                self.assertEqual(appmod.sphaira_screenshot_api('0100AAAABBBB0000', 1).status_code, 404)
                fetch.assert_not_called()


class SphairaScreenshotCacheTests(unittest.TestCase):
    def test_jpeg_renditions_are_cached_by_source_and_size(self):
        data = io.BytesIO()
        Image.new('RGBA', (1600, 900), (50, 100, 150, 255)).save(data, format='PNG')
        with tempfile.TemporaryDirectory(dir='.tmp') as directory, patch('app.sphaira.requests.get') as get:
            get.return_value.__enter__.return_value.iter_content.return_value = [data.getvalue()]
            source = 'https://example.invalid/screen.png'
            client = cached_screenshot(directory, '0100AAAABBBB0000', 0, source, 'CLIENT')
            with Image.open(client) as image:
                self.assertEqual(image.format, 'JPEG')
                self.assertEqual(image.size, (720, 405))
            self.assertEqual(cached_screenshot(directory, '0100AAAABBBB0000', 0, source, 'CLIENT'), client)
            get.assert_called_once_with(source, stream=True, timeout=(5, 20))
            full = cached_screenshot(directory, '0100AAAABBBB0000', 0, source, 'SCREEN')
            with Image.open(full) as image:
                self.assertEqual(image.size, (1280, 720))
            changed = cached_screenshot(directory, '0100AAAABBBB0000', 0, source + '?revision=2', 'CLIENT')
            self.assertNotEqual(changed, client)

    def test_invalid_or_oversized_download_is_not_cached(self):
        with tempfile.TemporaryDirectory(dir='.tmp') as directory, patch('app.sphaira.requests.get') as get:
            get.return_value.__enter__.return_value.iter_content.return_value = [b'not an image']
            with self.assertRaises(OSError):
                cached_screenshot(directory, '0100AAAABBBB0000', 0, 'https://example.invalid/screen.jpg', 'CLIENT')
            self.assertEqual(list(Path(directory).iterdir()), [])
            with patch('app.sphaira.MAX_SCREENSHOT_BYTES', 4), self.assertRaises(ValueError):
                cached_screenshot(directory, '0100AAAABBBB0000', 0, 'https://example.invalid/screen.jpg', 'CLIENT')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_screenshot_source_validation(self):
        self.assertEqual(screenshot_source('//example.invalid/image.jpg'), 'https://example.invalid/image.jpg')
        for value in ('', None, '/static/image.jpg', 'file:///fixture.jpg', 'https://['):
            self.assertIsNone(screenshot_source(value))


if __name__ == '__main__':
    unittest.main()
