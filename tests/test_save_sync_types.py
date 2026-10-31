"""Exercise the save routes without starting the app's DB, watchers, or schedulers."""
import ast
import io
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time
from types import SimpleNamespace
import unittest
import zipfile

from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename


ROOT = Path(__file__).resolve().parents[1]
TITLE = '0100000000000001'


def load_save_routes():
    # Compile the actual helpers and route bodies; access-control decorator tests
    # live in test_save_sync_access.py. This keeps fixtures away from real data.
    source = (ROOT / 'app' / 'app.py').read_text(encoding='utf-8')
    names = {'api_error', 'api_success', 'upload_save_api', 'list_saves_api',
             'download_save_api', 'delete_save_api', 'save_capabilities_api'}
    functions = [node for node in ast.parse(source).body
                 if isinstance(node, ast.FunctionDef) and
                 (node.name.startswith(('_save_sync_', '_normalize_save_')) or node.name in names)]
    for node in functions:
        node.decorator_list = []
    namespace = dict(os=os, json=json, re=re, secrets=secrets, shutil=shutil,
                     time=time, zipfile=zipfile, logger=logging.getLogger(__name__),
                     request=request, g=g, jsonify=jsonify,
                     send_from_directory=send_from_directory, secure_filename=secure_filename,
                     MAX_TITLE_ID_LENGTH=16, MAX_SAVE_ID_LENGTH=96,
                     MAX_SAVE_NOTE_LENGTH=120, MAX_SAVE_UPLOAD_SIZE=1024 * 1024,
                     SAVE_ID_RE=re.compile(r'^[A-Za-z0-9._-]+$'),
                     _is_cyberfoil_request=lambda: True,
                     titles=SimpleNamespace(load_titledb=lambda: False, release_titledb=lambda: None))
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(ROOT / 'app/app.py'), 'exec'), namespace)
    return namespace


def archive_bytes(value):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('slot.bin', value)
    output.seek(0)
    return output


class SaveTypeTests(unittest.TestCase):
    def setUp(self):
        scratch_root = ROOT / '.tmp'
        scratch_root.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(prefix='save-types-', dir=scratch_root)
        self.addCleanup(self.scratch.cleanup)
        self.ns = load_save_routes()
        self.ns['SAVE_SYNC_DIR'] = self.scratch.name
        self.user = SimpleNamespace(user='example-user', id=1)
        self.app = Flask(__name__)
        self.app.testing = True
        self.app.before_request(lambda: setattr(g, 'save_sync_user', self.user))
        for path, name, methods in [
            ('/api/saves/capabilities', 'save_capabilities_api', ['GET']),
            ('/api/saves/list', 'list_saves_api', ['GET']),
            ('/api/saves/upload/<title_id>', 'upload_save_api', ['POST']),
            ('/api/saves/download/<title_id>/<save_id>.zip', 'download_save_api', ['GET']),
            ('/api/saves/download/<title_id>.zip', 'download_save_api', ['GET']),
            ('/api/saves/delete/<title_id>/<save_id>', 'delete_save_api', ['DELETE']),
        ]:
            self.app.add_url_rule(path, endpoint=path, view_func=self.ns[name], methods=methods)
        self.client = self.app.test_client()

    def upload(self, save_type, value):
        data = {'file': (archive_bytes(value), 'example.zip'), 'note': 'Example checkpoint'}
        if save_type is not None:
            data['save_type'] = save_type
        response = self.client.post(f'/api/saves/upload/{TITLE}', data=data)
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()

    def download_value(self, url, expected_type):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Save-Type'], expected_type)
        try:
            with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
                return archive.read('slot.bin')
        finally:
            response.close()

    def test_account_device_and_unknown_histories_and_latest_are_separate(self):
        self.ns['_save_sync_generate_save_id'] = lambda note='': 'same-version'
        account = self.upload('account', b'account-data')
        device = self.upload('device', b'device-data')
        unknown = self.upload(None, b'old-client-data')
        for version, kind, value in [(account, 'account', b'account-data'),
                                     (device, 'device', b'device-data'),
                                     (unknown, 'unknown', b'old-client-data')]:
            self.assertEqual(version['save_type'], kind)
            self.assertEqual(self.download_value(version['download_url'], kind), value)
            self.assertEqual(self.download_value(f'/api/saves/download/{TITLE}/latest.zip?save_type={kind}', kind), value)
            metadata_path = self.ns['_save_sync_metadata_path'](self.user, TITLE, 'same-version', save_type=kind)
            self.assertEqual(json.loads(Path(metadata_path).read_text())['save_type'], kind)
        listed = self.client.get('/api/saves/list?save_types=1').get_json()
        self.assertTrue(listed['save_types'])
        self.assertEqual({row['save_type'] for row in listed['saves']}, {'account', 'device', 'unknown'})
        for kind in ('account', 'device', 'unknown'):
            rows = self.client.get('/api/saves/list?save_type=' + kind).get_json()['saves']
            self.assertTrue(rows)
            self.assertEqual({row['save_type'] for row in rows}, {kind})
            self.assertTrue(all('save_type=' + kind in row['download_url'] for row in rows))

    def test_legacy_clients_never_receive_typed_backups(self):
        self.upload('account', b'account')
        self.upload('device', b'device')
        self.assertEqual(self.client.get('/api/saves/list').get_json()['saves'], [])
        response = self.client.get(f'/api/saves/download/{TITLE}.zip')
        self.assertEqual(response.status_code, 404)
        response.close()

    def test_old_single_zip_is_preserved_as_unknown(self):
        legacy = Path(self.ns['_save_sync_archive_path'](self.user, TITLE))
        legacy.parent.mkdir(parents=True)
        original = archive_bytes(b'legacy-data').getvalue()
        legacy.write_bytes(original)
        self.upload('device', b'device')
        self.assertEqual(legacy.read_bytes(), original)
        listed = self.client.get('/api/saves/list').get_json()['saves']
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]['save_type'], 'unknown')
        self.assertEqual(self.download_value(listed[0]['download_url'], 'unknown'), b'legacy-data')

    def test_delete_and_latest_refresh_never_touch_other_types(self):
        self.ns['_save_sync_generate_save_id'] = lambda note='': 'same-version'
        account = self.upload('account', b'account')
        device = self.upload('device', b'device')
        response = self.client.delete(account['delete_url'])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.download_value(device['download_url'], 'device'), b'device')
        self.assertEqual(self.download_value(f'/api/saves/download/{TITLE}/latest.zip?save_type=device', 'device'), b'device')
        self.assertEqual(self.client.get('/api/saves/list?save_type=account').get_json()['saves'], [])

    def test_invalid_types_and_conflicting_form_and_query_are_rejected(self):
        for value in ('../device', 'system', 'account/device'):
            response = self.client.post(f'/api/saves/upload/{TITLE}', data={'save_type': value, 'file': (archive_bytes(b'x'), 'example.zip')})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(self.client.get('/api/saves/list?save_type=' + value).status_code, 400)
        response = self.client.post(f'/api/saves/upload/{TITLE}?save_type=device', data={'save_type': 'account', 'file': (archive_bytes(b'x'), 'example.zip')})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(os.listdir(self.scratch.name), [])

    def test_backup_ownership_remains_separate_from_save_type(self):
        saved = self.upload('device', b'private-data')
        self.user = SimpleNamespace(user='other-user', id=2)
        self.assertEqual(self.client.get(saved['download_url']).status_code, 404)
        self.assertEqual(self.client.delete(saved['delete_url']).status_code, 404)
        self.assertEqual(self.client.get('/api/saves/list?save_types=1').get_json()['saves'], [])

    def test_capabilities_advertise_supported_types(self):
        payload = self.client.get('/api/saves/capabilities').get_json()
        self.assertTrue(payload['save_types'])
        self.assertEqual(payload['types'], ['unknown', 'account', 'device'])


if __name__ == '__main__':
    unittest.main()
