import os
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from app import metadata_sources, settings, titledb, titles


BASE_ID = '0100AAAA00000000'
UPDATE_ID = '0100AAAA00000800'
DLC_ID = '0100AAAA00001001'
ENABLED = {'metadata_sources': {'nx_versions_enabled': True}}
DATA = f'id|version\n{UPDATE_ID.lower()}|131072\n{DLC_ID}|0\n'
UPSTREAM = {'revision': 'a' * 40, 'last_updated': '2020-01-02T03:04:05+00:00', 'etag': '"commit-etag"'}
CHANGELOG = f'''## 2020-01-03 22:37
```
[Added: 1]
[{DLC_ID}][v0]
[Updated: 1]
[{UPDATE_ID}][v65536]->[v131072]
```
## 2020-01-02 22:36 (Initial Upload)
```
[Added: 1]
[{UPDATE_ID.lower()}][v65536]
[Updated: 1]
[{UPDATE_ID}][v0]->[v131072]
```
'''


class MetadataSourcesTests(unittest.TestCase):
    def setUp(self):
        os.makedirs('.tmp', exist_ok=True)
        self.temp = TemporaryDirectory(dir='.tmp')
        self.addCleanup(self.temp.cleanup)
        self.directory_patch = patch.object(metadata_sources, 'TITLEDB_DIR', self.temp.name)
        self.directory_patch.start()
        self.addCleanup(self.directory_patch.stop)
        self.path = os.path.join(self.temp.name, 'nx-versions.txt')
        self.upstream_patch = patch.object(metadata_sources, '_get_upstream_update', return_value=UPSTREAM)
        self.upstream_patch.start()
        self.addCleanup(self.upstream_patch.stop)
        self.changelog_patch = patch.object(metadata_sources, '_update_changelog', return_value=None)
        self.changelog_patch.start()
        self.addCleanup(self.changelog_patch.stop)

    def write_cache(self, data=DATA):
        previous_mtime = os.stat(self.path).st_mtime_ns if os.path.isfile(self.path) else None
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(data)
        if previous_mtime is not None:
            # Windows can coalesce timestamps on rapid same-size writes.
            os.utime(self.path, ns=(previous_mtime + 1000000000, previous_mtime + 1000000000))

    def test_parse_real_format_normalizes_ids_and_keeps_highest_duplicate(self):
        parsed = metadata_sources.parse_nx_versions(DATA + f'{UPDATE_ID}|65536\n')
        self.assertEqual(parsed, {UPDATE_ID: 131072, DLC_ID: 0})

    def build_date_index(self):
        self.changelog_patch.stop()
        with patch.object(metadata_sources.requests, 'get', return_value=Mock(
            status_code=200, content=CHANGELOG.encode(), headers={}
        )):
            self.assertIsNone(metadata_sources._update_changelog(UPSTREAM))

    def test_changelog_dates_use_first_observation_and_only_new_version(self):
        dates = metadata_sources.parse_nx_changelog(CHANGELOG)
        self.assertEqual(dates[(UPDATE_ID, 131072)], '2020-01-02')
        self.assertEqual(dates[(UPDATE_ID, 65536)], '2020-01-02')
        self.assertNotIn((UPDATE_ID, 0), dates)
        self.assertEqual(dates[(DLC_ID, 0)], '2020-01-03')

    def test_changelog_index_reused_without_download_or_parse(self):
        before = metadata_sources.get_metadata_cache_token()
        self.build_date_index()
        after = metadata_sources.get_metadata_cache_token()
        self.assertNotEqual(before, after)
        with patch.object(metadata_sources.requests, 'get') as get, patch.object(
            metadata_sources, 'parse_nx_changelog'
        ) as parse:
            self.assertIsNone(metadata_sources._update_changelog(UPSTREAM))
            for _ in range(5):
                self.assertEqual(metadata_sources.get_version_dates(UPDATE_ID.lower(), ENABLED)[131072], '2020-01-02')
            get.assert_not_called()
            parse.assert_not_called()
        self.assertEqual(metadata_sources.get_metadata_cache_token(), after)
        self.assertEqual(metadata_sources.get_version_dates(UPDATE_ID, {}), {})

    def test_failed_changelog_refresh_retains_index(self):
        self.build_date_index()
        next_upstream = dict(UPSTREAM, revision='b' * 40)
        for kwargs in ({'side_effect': OSError('offline')}, {'return_value': Mock(status_code=200, content=b'bad', headers={})}):
            with patch.object(metadata_sources.requests, 'get', **kwargs):
                self.assertTrue(metadata_sources._update_changelog(next_upstream))
            self.assertEqual(metadata_sources.get_version_dates(UPDATE_ID, ENABLED)[131072], '2020-01-02')

    def test_missing_dates_are_backfilled_when_versions_download_is_unchanged(self):
        response = Mock(content=DATA.encode(), status_code=200, headers={'ETag': '"example"'})
        with patch.object(metadata_sources.requests, 'get', return_value=response):
            metadata_sources.update_metadata_sources(ENABLED)
        self.changelog_patch.stop()
        with patch.object(metadata_sources.requests, 'get', side_effect=[
            Mock(status_code=304),
            Mock(status_code=200, content=CHANGELOG.encode(), headers={}),
        ]) as get:
            self.assertIsNone(metadata_sources.update_metadata_sources(ENABLED))
            self.assertEqual(get.call_count, 2)
        self.assertEqual(metadata_sources.get_version_dates(UPDATE_ID, ENABLED)[131072], '2020-01-02')

    def test_invalid_changelog_is_rejected(self):
        for text in ('', 'error page', f'[{UPDATE_ID}][v65536]',
                     f'## 2020-99-99 22:37\n[{UPDATE_ID}][v65536]',
                     f'## 2020-01-01 22:37\n[{UPDATE_ID}][v4294967296]'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                metadata_sources.parse_nx_changelog(text)

    def test_release_dates_fill_missing_primary_dates_without_overwriting_known_dates(self):
        self.write_cache()
        self.build_date_index()
        primary = [{'version': 65536, 'release_date': '2019-12-31', 'update_number': 1}]
        with patch.object(titles, 'load_settings', return_value=ENABLED), patch.object(
            titles, '_get_titledb_existing_versions', return_value=primary
        ):
            versions = titles.get_all_existing_versions(BASE_ID)
        self.assertEqual(versions[0]['release_date'], '2019-12-31')
        self.assertEqual(versions[1]['release_date'], '2020-01-02')
        primary[0]['release_date'] = None
        with patch.object(titles, 'load_settings', return_value=ENABLED), patch.object(
            titles, '_get_titledb_existing_versions', return_value=primary
        ):
            self.assertEqual(titles.get_all_existing_versions(BASE_ID)[0]['release_date'], '2020-01-02')

    def test_rejects_invalid_or_empty_data(self):
        for data in ('', 'id|version\n', '<html>Error</html>', 'id|version\ninvalid|1',
                     f'id|version\n{UPDATE_ID}|-1', f'id|version\n{UPDATE_ID}|4294967296'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                metadata_sources.parse_nx_versions(data)

    def test_disabled_source_does_not_download_or_use_cache(self):
        self.write_cache()
        with patch.object(metadata_sources.requests, 'get') as get:
            self.assertIsNone(metadata_sources.update_metadata_sources({}))
            self.assertIsNone(metadata_sources.get_latest_version(UPDATE_ID, {}))
            get.assert_not_called()

    def test_successful_download_and_cache_refresh(self):
        response = Mock(content=DATA.encode(), status_code=200, headers={})
        with patch.object(metadata_sources.requests, 'get', return_value=response):
            self.assertIsNone(metadata_sources.update_metadata_sources(ENABLED))
        response.close.assert_called_once()
        self.assertEqual(metadata_sources.get_metadata_source_status()['nx-versions']['last_updated'], UPSTREAM['last_updated'])
        self.assertEqual(metadata_sources.get_latest_version(UPDATE_ID.lower(), ENABLED), 131072)
        self.write_cache(DATA.replace('131072', '262144'))
        self.assertEqual(metadata_sources.get_latest_version(UPDATE_ID, ENABLED), 262144)

    def test_network_and_invalid_payload_failures_preserve_cached_data(self):
        self.write_cache()
        metadata_sources.record_source_update('nx-versions', UPSTREAM)
        before = metadata_sources.get_metadata_source_status()
        for kwargs in ({'side_effect': OSError('offline')}, {'return_value': Mock(content=b'bad')}):
            with patch.object(metadata_sources.requests, 'get', **kwargs):
                self.assertTrue(metadata_sources.update_metadata_sources(ENABLED))
            self.assertEqual(metadata_sources.get_latest_version(UPDATE_ID, ENABLED), 131072)
            self.assertFalse(os.path.exists(self.path + '.tmp'))
            self.assertEqual(metadata_sources.get_metadata_source_status(), before)

    def test_status_handles_missing_invalid_and_persisted_timestamps(self):
        self.assertIsNone(metadata_sources.get_metadata_source_status()['titledb']['last_updated'])
        metadata_sources.record_source_update('titledb', UPSTREAM)
        first = metadata_sources.get_metadata_source_status()['titledb']['last_updated']
        self.assertTrue(first.endswith('+00:00'))
        self.assertEqual(first, UPSTREAM['last_updated'])
        self.assertEqual(metadata_sources.get_metadata_source_status()['titledb']['last_updated'], first)
        with open(os.path.join(self.temp.name, '.nx-versions-updated'), 'w', encoding='utf-8') as handle:
            handle.write('invalid timestamp')
        self.assertIsNone(metadata_sources.get_metadata_source_status()['nx-versions']['last_updated'])
        # Old server-refresh markers must never become upstream update dates.
        with open(os.path.join(self.temp.name, '.nx-versions-refreshed'), 'w', encoding='utf-8') as handle:
            handle.write('2026-10-12T00:00:00+00:00')
        self.assertIsNone(metadata_sources.get_metadata_source_status()['nx-versions']['last_updated'])

    def test_upstream_commit_metadata_is_small_conditional_and_cached(self):
        self.upstream_patch.stop()
        response = Mock(status_code=200, headers={'ETag': '"example-api-etag"'})
        response.json.return_value = [{'sha': UPSTREAM['revision'], 'commit': {
            'committer': {'date': '2020-01-02T03:04:05Z'}
        }}]
        with patch.object(metadata_sources.requests, 'get', return_value=response) as get:
            data = metadata_sources._get_upstream_update('nx-versions')
            self.assertEqual(data['last_updated'], UPSTREAM['last_updated'])
            self.assertEqual(get.call_args.kwargs['params'], {'path': 'versions.txt', 'sha': 'master', 'per_page': 1})
            metadata_sources.record_source_update('nx-versions', data)
        response = Mock(status_code=304)
        with patch.object(metadata_sources.requests, 'get', return_value=response) as get:
            self.assertEqual(metadata_sources._get_upstream_update('nx-versions'), data)
            self.assertEqual(get.call_args.kwargs['headers']['If-None-Match'], '"example-api-etag"')
            response.json.assert_not_called()

    def test_titledb_date_is_looked_up_for_exact_artifact_revision_once(self):
        self.upstream_patch.stop()
        response = Mock(status_code=200, headers={})
        response.json.return_value = [{'sha': UPSTREAM['revision'], 'commit': {
            'committer': {'date': '2020-01-02T03:04:05Z'}
        }}]
        with patch.object(metadata_sources.requests, 'get', return_value=response) as get:
            for _ in range(2):
                metadata_sources.update_titledb_source_status('aaaaaaa', self.temp.name)
            get.assert_called_once()
            self.assertEqual(get.call_args.kwargs['params'], {'sha': 'aaaaaaa', 'per_page': 1})
        self.assertEqual(metadata_sources.get_metadata_source_status()['titledb']['last_updated'], UPSTREAM['last_updated'])

    def test_upstream_metadata_failure_does_not_block_data_download(self):
        with patch.object(metadata_sources, '_get_upstream_update', return_value={}), patch.object(
            metadata_sources.requests, 'get', return_value=Mock(content=DATA.encode(), status_code=200, headers={})
        ):
            self.assertIsNone(metadata_sources.update_metadata_sources(ENABLED))
        self.assertEqual(metadata_sources.get_latest_version(UPDATE_ID, ENABLED), 131072)
        self.assertIsNone(metadata_sources.get_metadata_source_status()['nx-versions']['last_updated'])

    def test_data_is_pinned_to_commit_matching_displayed_date(self):
        with patch.object(metadata_sources.requests, 'get', return_value=Mock(content=DATA.encode(), status_code=200, headers={})) as get:
            metadata_sources.update_metadata_sources(ENABLED)
        self.assertIn('/' + UPSTREAM['revision'] + '/versions.txt', get.call_args.args[0])

    def test_titledb_uses_source_commit_date_and_failure_preserves_it(self):
        metadata_sources.update_titledb_source_status(UPSTREAM['revision'], self.temp.name)
        before = metadata_sources.get_metadata_source_status()['titledb']['last_updated']
        self.assertEqual(before, UPSTREAM['last_updated'])
        with patch.object(titledb, 'TITLEDB_DIR', self.temp.name), patch.object(titledb, 'update_titledb_files', side_effect=ValueError('offline')):
            with self.assertRaises(ValueError):
                titledb.update_titledb({})
            self.assertEqual(metadata_sources.get_metadata_source_status()['titledb']['last_updated'], before)

    def test_unchanged_refresh_skips_body_and_reuses_persisted_validators(self):
        response = Mock(content=DATA.encode(), status_code=200,
                        headers={'ETag': '"example-etag"', 'Last-Modified': 'Mon, 12 Oct 2026 10:00:00 GMT'})
        with patch.object(metadata_sources.requests, 'get', return_value=response):
            metadata_sources.update_metadata_sources(ENABLED)
        before = os.stat(self.path).st_mtime_ns
        # Simulate a restart: validators and the parsed cache must survive/reload correctly.
        with patch.object(metadata_sources, '_cache_signature', None), patch.object(
            metadata_sources, 'parse_nx_versions', wraps=metadata_sources.parse_nx_versions
        ) as parse, patch.object(metadata_sources.requests, 'get', return_value=Mock(status_code=304)) as get:
            self.assertIsNone(metadata_sources.update_metadata_sources(ENABLED))
            for _ in range(10):
                self.assertEqual(metadata_sources.get_latest_version(UPDATE_ID, ENABLED), 131072)
            parse.assert_called_once()
            self.assertEqual(get.call_args.kwargs['headers'], {
                'If-None-Match': '"example-etag"',
                'If-Modified-Since': 'Mon, 12 Oct 2026 10:00:00 GMT',
            })
            get.return_value.close.assert_called_once()
            get.return_value.raise_for_status.assert_not_called()
            self.assertEqual(metadata_sources.get_metadata_source_status()['nx-versions']['last_updated'], UPSTREAM['last_updated'])
        self.assertEqual(os.stat(self.path).st_mtime_ns, before)

    def test_refresh_primes_lookup_cache_without_reparsing_download(self):
        response = Mock(content=DATA.encode(), status_code=200, headers={'ETag': '"example"'})
        with patch.object(metadata_sources.requests, 'get', return_value=response), patch.object(
            metadata_sources, 'parse_nx_versions', wraps=metadata_sources.parse_nx_versions
        ) as parse:
            metadata_sources.update_metadata_sources(ENABLED)
            for _ in range(10):
                self.assertEqual(metadata_sources.get_latest_version(UPDATE_ID, ENABLED), 131072)
            parse.assert_called_once()

    def test_missing_or_changed_cache_does_not_send_stale_validators(self):
        response = Mock(content=DATA.encode(), status_code=200, headers={'ETag': '"example"'})
        with patch.object(metadata_sources.requests, 'get', return_value=response):
            metadata_sources.update_metadata_sources(ENABLED)
        self.write_cache(DATA.replace('131072', '196608'))
        self.assertEqual(metadata_sources._conditional_headers(self.path), {})
        os.remove(self.path)
        self.assertEqual(metadata_sources._conditional_headers(self.path), {})

    def test_invalid_cache_triggers_unconditional_recovery(self):
        response = Mock(content=DATA.encode(), status_code=200, headers={'ETag': '"example"'})
        with patch.object(metadata_sources.requests, 'get', return_value=response) as get:
            metadata_sources.update_metadata_sources(ENABLED)
            self.write_cache('invalid')
            self.assertIsNone(metadata_sources.update_metadata_sources(ENABLED))
            self.assertEqual(get.call_args.kwargs['headers'], {})
        self.assertEqual(metadata_sources.get_latest_version(UPDATE_ID, ENABLED), 131072)

    def test_title_versions_merge_without_duplicates_or_invented_history(self):
        self.write_cache()
        primary = [{'version': 65536, 'update_number': 1, 'release_date': '2020-01-01'}]
        with patch.object(titles, 'load_settings', return_value=ENABLED), patch.object(
            titles, '_get_titledb_existing_versions', return_value=primary.copy()
        ):
            versions = titles.get_all_existing_versions(BASE_ID.lower())
        self.assertEqual([v['version'] for v in versions], [65536, 131072])
        self.assertEqual(versions[1]['release_date'], 'Unknown')
        with patch.object(titles, 'load_settings', return_value=ENABLED), patch.object(
            titles, '_get_titledb_existing_versions', return_value=versions.copy()
        ):
            self.assertEqual(titles.get_all_existing_versions(BASE_ID), versions)

    def test_supplement_works_without_titledb_index_and_disable_removes_it(self):
        self.write_cache()
        with patch.object(titles, '_versions_index_ready', False), patch.object(
            titles, 'load_settings', return_value=ENABLED
        ):
            self.assertEqual(titles.get_all_existing_versions(BASE_ID)[0]['version'], 131072)
        with patch.object(titles, '_versions_index_ready', False), patch.object(
            titles, 'load_settings', return_value={}
        ):
            self.assertEqual(titles.get_all_existing_versions(BASE_ID), [])

    def test_dlc_latest_version_supplements_primary(self):
        self.write_cache(DATA.replace(f'{DLC_ID}|0', f'{DLC_ID}|196608'))
        with patch.object(titles, 'load_settings', return_value=ENABLED), patch.object(
            titles, '_get_titledb_app_existing_versions', return_value=['65536']
        ):
            self.assertEqual(set(titles.get_all_app_existing_versions(DLC_ID)), {'65536', '196608'})

    def test_optional_source_refresh_runs_even_when_titledb_fails(self):
        with patch.object(titledb, 'TITLEDB_DIR', self.temp.name), patch.object(
            metadata_sources, 'update_metadata_sources'
        ) as refresh, patch.object(titledb, 'update_titledb_files', side_effect=ValueError('offline')):
            with self.assertRaises(ValueError):
                titledb.update_titledb(ENABLED)
            refresh.assert_called_once_with(ENABLED)

    def test_settings_defaults_coercion_and_persistence(self):
        self.assertEqual(settings._normalize_metadata_sources_settings({}), {'nx_versions_enabled': True})
        self.assertFalse(settings._normalize_metadata_sources_settings({'nx_versions_enabled': 'false'})['nx_versions_enabled'])
        self.assertTrue(settings._normalize_metadata_sources_settings({'nx_versions_enabled': 'true'})['nx_versions_enabled'])
        config = os.path.join(self.temp.name, 'config.yaml')
        with patch.object(settings, 'CONFIG_FILE', config), patch.object(settings, 'KEYS_FILE', config + '.keys'), patch.object(settings, 'load_keys', return_value=False):
            settings._invalidate_settings_cache()
            self.addCleanup(settings._invalidate_settings_cache)
            self.assertTrue(settings.load_settings(force_reload=True)['metadata_sources']['nx_versions_enabled'])
            settings.set_metadata_sources_settings({'nx_versions_enabled': True})
            self.assertTrue(settings.load_settings(force_reload=True)['metadata_sources']['nx_versions_enabled'])
            settings.set_metadata_sources_settings({'nx_versions_enabled': False})
            self.assertFalse(settings.load_settings(force_reload=True)['metadata_sources']['nx_versions_enabled'])


class MetadataSourcesApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import app as app_module
        cls.app_module = app_module

    def test_save_refreshes_source_and_schedules_library_rebuild(self):
        module = self.app_module
        with module.app.test_request_context('/api/settings/metadata-sources', method='POST', json={'nx_versions_enabled': True}), patch.object(
            module, 'set_metadata_sources_settings'
        ) as save, patch.object(module, 'reload_conf') as reload, patch.object(
            module.metadata_sources, 'update_metadata_sources', return_value='Cached data retained.'
        ) as refresh, patch.object(module, 'post_library_change') as rebuild:
            response = module.set_metadata_sources_settings_api.__wrapped__()
        self.assertTrue(response.get_json()['success'])
        self.assertEqual(response.get_json()['warning'], 'Cached data retained.')
        save.assert_called_once_with({'nx_versions_enabled': True})
        reload.assert_called_once()
        refresh.assert_called_once()
        rebuild.assert_called_once()

    def test_rejects_invalid_payload_without_saving(self):
        module = self.app_module
        for payload in ({}, {'nx_versions_enabled': 'false'}, [], {'nx_versions_enabled': 1}):
            with self.subTest(payload=payload), module.app.test_request_context(
                '/api/settings/metadata-sources', method='POST', json=payload
            ), patch.object(module, 'set_metadata_sources_settings') as save:
                response, status = module.set_metadata_sources_settings_api.__wrapped__()
                self.assertEqual(status, 400)
                self.assertFalse(response.get_json()['success'])
                save.assert_not_called()

    def test_non_admin_cannot_save_sources(self):
        module = self.app_module
        user = Mock(is_authenticated=True)
        user.has_access.return_value = False
        with module.app.test_request_context('/api/settings/metadata-sources', method='POST', json={'nx_versions_enabled': True}), patch(
            'app.auth.admin_account_created', return_value=True
        ), patch('app.auth.current_user', user), patch.object(module, 'set_metadata_sources_settings') as save:
            _, status = module.set_metadata_sources_settings_api()
            self.assertEqual(status, 403)
            save.assert_not_called()


if __name__ == '__main__':
    unittest.main()
