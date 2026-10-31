import io
import json
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from contextlib import ExitStack, closing
from unittest.mock import patch

from app import titledb, titles


ROOT = Path(__file__).resolve().parents[1]
TITLE_ID = '0100000000001000'


class GeneratedTitleMetadataTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.tmp').mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=ROOT / '.tmp', prefix='generated-titles-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.settings = {'titles': {'region': 'US', 'language': 'en'}}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for module in (titles, titledb):
            self.stack.enter_context(patch.object(module, 'TITLEDB_DIR', str(self.root)))
        for name, filename in (
            ('_titles_index_file', 'titles.index.sqlite3'),
            ('_english_titles_index_file', 'english.index.sqlite3'),
            ('_versions_index_file', 'versions.index.sqlite3'),
            ('_cnmts_default_index_file', 'cnmts.index.sqlite3'),
            ('_cnmts_fixed_index_file', 'cnmts-fixed.index.sqlite3'),
        ):
            self.stack.enter_context(patch.object(titles, name, str(self.root / filename)))
        self.stack.enter_context(patch.object(titles, 'load_settings', return_value=self.settings))
        self.stack.enter_context(patch.object(titles, '_build_local_fallback_info', return_value=None))
        titles._reset_titledb_state()
        titles.identification_in_progress_count = 0
        self.addCleanup(titles._reset_titledb_state)
        self.addCleanup(setattr, titles, 'identification_in_progress_count', 0)
        self.files = {
            'cnmts.json': '{}', 'versions.json': '{}', 'languages.json': '{}',
            'versions.txt': f'{TITLE_ID}|ignored|0\n',
            'titles.US.en.json': json.dumps({TITLE_ID: {
                'id': TITLE_ID, 'name': 'Example Title',
                'description': 'Example description', 'rating': 10,
                'screenshots': [' https://example.invalid/shot.jpg ', None, '', 42],
            }}),
        }
        for filename, content in self.files.items():
            (self.root / filename).write_text(content, encoding='utf-8')

    def test_loads_descriptions_and_screenshots_without_raw_file_or_network(self):
        # An obsolete, corrupt raw file must have no effect on metadata loading.
        (self.root / 'US.en.json').write_text('{broken', encoding='utf-8')
        with patch('requests.get') as network, patch.object(
            titledb, 'update_titledb'
        ) as recover:
            self.assertTrue(titles.load_titledb())
            info = titles.get_game_info(TITLE_ID)
        network.assert_not_called()
        recover.assert_not_called()
        self.assertEqual(info['description'], 'Example description')
        self.assertEqual(info['screenshots'], ['https://example.invalid/shot.jpg'])
        self.assertEqual(info['rating'], 10)
        # Reopening a current index must reuse it without reparsing JSON.
        with patch.object(titles, '_load_json_file') as load:
            self.assertTrue(titles._ensure_titles_index(str(self.root / 'titles.US.en.json')))
        load.assert_not_called()

    def test_older_index_rebuilds_once_without_redownloading_data(self):
        source = str(self.root / 'titles.US.en.json')
        with patch.object(titles, 'TITLES_INDEX_SCHEMA_VERSION', 'rating-v1'):
            titles._ensure_titles_index(source)
        with closing(sqlite3.connect(titles._titles_index_file)) as conn:
            conn.execute('ALTER TABLE titles DROP COLUMN screenshots')
        self.assertTrue(titles._ensure_titles_index(source))
        self.assertEqual(titles.get_game_info(TITLE_ID)['screenshots'],
                         ['https://example.invalid/shot.jpg'])

    def test_english_preference_includes_screenshots_and_keeps_localized_fallback(self):
        self.settings['titles']['prefer_english_metadata'] = True
        english = {TITLE_ID: {
            'id': TITLE_ID, 'name': 'Example English Title',
            'description': 'Example English description',
            'screenshots': ['https://example.invalid/english.jpg'],
        }}
        # Prefer English from the current region before US English.
        path = self.root / 'titles.JP.en.json'
        path.write_text(json.dumps(english), encoding='utf-8')
        self.settings['titles'].update(region='JP', language='ja')
        (self.root / 'titles.JP.ja.json').write_text(
            self.files['titles.US.en.json'], encoding='utf-8')
        self.assertTrue(titles.load_titledb())
        info = titles.get_game_info(TITLE_ID)
        self.assertEqual(info['description'], 'Example English description')
        self.assertEqual(info['screenshots'], ['https://example.invalid/english.jpg'])
        # Empty English fields preserve the selected region's metadata.
        merged = titles._merge_preferred_title_info(info, {'description': '', 'screenshots': []})
        self.assertEqual(merged['description'], info['description'])
        self.assertEqual(merged['screenshots'], info['screenshots'])

    def test_missing_or_invalid_screenshots_are_empty_and_lists_are_capped(self):
        for value in (None, '', {}, ['']):
            with self.subTest(value=value):
                self.assertEqual(titles._normalize_screenshots(value), [])
        shots = [f'https://example.invalid/{i}.jpg' for i in range(20)]
        self.assertEqual(titles._normalize_screenshots(shots), shots[:12])

    def test_updates_only_download_generated_artifact_files(self):
        for unchanged in (False, True):
            with self.subTest(unchanged=unchanged):
                marker = 'example-current' if unchanged else 'example-new'
                (self.root / '.latest').write_text('example-current', encoding='utf-8')
                remote = types.SimpleNamespace(
                    infolist=lambda: [types.SimpleNamespace(filename=name)
                                      for name in [f'latest_{marker}', *self.files]],
                    open=lambda name: io.BytesIO(self.files[name].encode()),
                )
                with patch.object(titledb, '_get_with_retry', return_value=types.SimpleNamespace(
                    status_code=302, headers={'Location': 'https://example.invalid/titledb.zip'}
                )) as request, patch.object(
                    titledb.unzip_http, 'RemoteZipFile', return_value=remote
                ), patch('app.metadata_sources.update_titledb_source_status'), patch(
                    'requests.get'
                ) as direct_request:
                    titledb.update_titledb_files(self.settings)
                request.assert_called_once_with(titledb.TITLEDB_ARTEFACTS_URL, allow_redirects=False)
                direct_request.assert_not_called()
                self.assertFalse((self.root / 'US.en.json').exists())


if __name__ == '__main__':
    unittest.main()
