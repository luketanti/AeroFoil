import io
import json
from pathlib import Path
import random
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import zstandard

from app import titledb


ROOT = Path(__file__).resolve().parents[1]


class TitleDBCompressionTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.tmp').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / '.tmp')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.patch_directory = patch.object(titledb, 'TITLEDB_DIR', str(self.directory))
        self.patch_directory.start()
        self.addCleanup(self.patch_directory.stop)
        self.settings = {'titles': {'region': 'JP', 'language': 'ja',
                                    'prefer_english_metadata': True}}

    def archive(self, files):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        archive = zipfile.ZipFile(buffer)
        self.addCleanup(archive.close)
        return archive

    def fixture(self):
        return {
            'cnmts.json': b'{}',
            'cnmts-fixed.json': b'{"example": {}}',
            'versions.json': b'{}',
            'versions.txt': b'id|version\n',
            'languages.json': b'{"JP": ["ja"], "US": ["en"], "GB": ["en"]}',
            'titles.JP.ja.json': json.dumps({
                '0100000000001000': {'name': 'Example Title', 'description': '\u65e5\u672c\u8a9e'},
            }, ensure_ascii=False).encode('utf-8'),
            'titles.US.en.json': b'{"0100000000001000": {"name": "Example Title"}}',
            'titles.GB.en.json': b'{}',
        }

    def encode_files(self, files, mode):
        result = {'latest_example123': b''}
        for index, (name, content) in enumerate(files.items()):
            if name.endswith('.json') and (mode == 'compressed' or (mode == 'mixed' and index % 2)):
                result[name + '.zst'] = zstandard.ZstdCompressor(
                    level=9, write_content_size=False,
                ).compress(content)
            else:
                result[name] = content
        return result

    def update(self, archive):
        response = types.SimpleNamespace(status_code=302, headers={'Location': 'https://example.invalid/titledb.zip'})
        with patch.object(titledb, '_get_with_retry', return_value=response), \
                patch.object(titledb.unzip_http, 'RemoteZipFile', return_value=archive), \
                patch('app.metadata_sources.update_titledb_source_status'):
            titledb.update_titledb_files(self.settings)

    def test_updates_from_legacy_compressed_and_mixed_artifacts(self):
        expected = self.fixture()
        for mode in ('plain', 'compressed', 'mixed'):
            with self.subTest(mode=mode):
                for path in self.directory.iterdir():
                    path.unlink()
                archive = self.archive(self.encode_files(expected, mode))
                self.update(archive)
                for name, content in expected.items():
                    self.assertEqual((self.directory / name).read_bytes(), content)
                self.assertEqual((self.directory / '.latest').read_text(), 'example123')
                self.assertFalse(list(self.directory.glob('*.zst')))
                self.assertFalse(list(self.directory.glob('*.tmp')))

    def test_discovers_missing_compressed_optional_and_english_files_without_new_commit(self):
        files = self.fixture()
        for name in titledb.TITLEDB_DEFAULT_FILES + ['titles.JP.ja.json']:
            (self.directory / name).write_bytes(files[name])
        (self.directory / '.latest').write_text('example123')
        archive = self.archive(self.encode_files(files, 'compressed'))
        with patch.object(archive, 'open', wraps=archive.open) as opened:
            self.update(archive)
        self.assertEqual({call.args[0] for call in opened.call_args_list}, {
            'titles.US.en.json.zst', 'titles.GB.en.json.zst', 'cnmts-fixed.json.zst',
        })
        for name, content in files.items():
            self.assertEqual((self.directory / name).read_bytes(), content)

    def test_prefers_compressed_json_when_both_formats_exist(self):
        name = 'titles.US.en.json'
        content = b'{"name": "Example Title"}'
        archive = self.archive({name: b'legacy', name + '.zst': zstandard.ZstdCompressor(level=9).compress(content)})
        titledb.download_titledb_files(archive, [name])
        self.assertEqual((self.directory / name).read_bytes(), content)

    def test_decompresses_frames_spanning_multiple_download_chunks(self):
        name = 'titles.US.en.json'
        content = json.dumps({'example': random.Random(42).randbytes(200000).hex()}).encode()
        compressed = zstandard.ZstdCompressor(level=9).compress(content)
        self.assertGreater(len(compressed), 65536)
        archive = self.archive({name + '.zst': compressed})
        titledb.download_titledb_files(archive, [name])
        self.assertEqual((self.directory / name).read_bytes(), content)

    def test_failed_compressed_update_preserves_existing_file_and_revision(self):
        valid = zstandard.ZstdCompressor(level=9).compress(b'{}')
        incomplete_checksum = zstandard.ZstdCompressor(write_checksum=True).compress(b'{}')[:-1]
        for content in (b'invalid zstd', valid[:-1], incomplete_checksum, valid + b'trailing',
                        zstandard.ZstdCompressor().compress(b'invalid JSON')):
            with self.subTest(content=content):
                name = 'titles.JP.ja.json'
                (self.directory / name).write_bytes(b'{"old": true}')
                (self.directory / '.latest').write_text('previous123')
                files = self.encode_files(self.fixture(), 'compressed')
                files[name + '.zst'] = content
                with self.assertRaises((ValueError, zstandard.ZstdError)):
                    self.update(self.archive(files))
                self.assertEqual((self.directory / name).read_bytes(), b'{"old": true}')
                self.assertEqual((self.directory / '.latest').read_text(), 'previous123')
                self.assertFalse(list(self.directory.glob('*.tmp')))


if __name__ == '__main__':
    unittest.main()
