import ast
import json
from pathlib import Path
import socket
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app import discovery
from app.settings import _normalize_shop_settings, verify_settings


class DiscoveryTests(unittest.TestCase):
    def tearDown(self):
        discovery.stop()

    def test_settings_are_opt_in_and_coerce_boolean(self):
        self.assertFalse(_normalize_shop_settings({})['discovery_enabled'])
        self.assertFalse(_normalize_shop_settings({'discovery_enabled': 'false'})['discovery_enabled'])
        self.assertTrue(_normalize_shop_settings({'discovery_enabled': 'true'})['discovery_enabled'])
        self.assertEqual(_normalize_shop_settings({'discovery_name': '  '})['discovery_name'], 'AeroFoil')

    def test_advertised_port_validation(self):
        for port in (0, 1, 65535, '9000'):
            with self.subTest(port=port):
                self.assertTrue(verify_settings('shop', {'discovery_http_port': port})[0])
        for port in (-1, 65536, 'invalid', None, True, 1.5):
            with self.subTest(port=port):
                success, errors = verify_settings('shop', {'discovery_http_port': port})
                self.assertFalse(success)
                self.assertTrue(any(e['path'] == 'shop/discovery_http_port' for e in errors))

    def test_uid_survives_restart_and_recovers_invalid_file(self):
        root = Path('.tmp')
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as directory:
            with patch.object(discovery, 'CONFIG_DIR', directory):
                uid = discovery._server_uid()
                self.assertEqual(discovery._server_uid(), uid)
                Path(directory, 'discovery_uid').write_text('invalid', encoding='utf-8')
                self.assertNotEqual(discovery._server_uid(), uid)

    def test_payload_contains_only_discovery_fields_and_port_override(self):
        shop = {'discovery_name': 'Example Server', 'discovery_http_port': 9000,
                'host': 'example.invalid', 'public': True, 'password': 'fixture-secret'}
        with patch.object(discovery, 'load_settings', return_value={'shop': shop}):
            payload = discovery.discovery_payload('fixture-id', 8465)
            self.assertEqual(payload, {'magic': 'OWNFOIL', 'uid': 'fixture-id',
                'name': 'Example Server', 'version': discovery.APP_VERSION,
                'port': 9000, 'remote': 'example.invalid', 'public': True})
            shop['discovery_http_port'] = 0
            self.assertEqual(discovery.discovery_payload('fixture-id', 8123)['port'], 8123)

    def test_real_udp_reply_ignores_unknown_requests_and_uses_live_settings(self):
        shop = {'discovery_name': 'Example Server'}
        with patch.object(discovery, 'load_settings', return_value={'shop': shop}):
            responder = discovery.DiscoveryResponder('fixture-id', 8123, port=0)
            responder.bind()
            responder.start()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(0.3)
                    destination = ('127.0.0.1', responder.port)
                    client.sendto(b'UNKNOWN', destination)
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(1024)
                    client.sendto(b'OWNFOIL_DISCOVER', destination)
                    payload = json.loads(client.recvfrom(1024)[0])
                    self.assertEqual(payload['magic'], 'OWNFOIL')
                    self.assertEqual(payload['uid'], 'fixture-id')
                    self.assertEqual(payload['port'], 8123)
                    shop['discovery_name'] = 'Example Changed Server'
                    client.sendto(b'OWNFOIL_DISCOVER', destination)
                    self.assertEqual(json.loads(client.recvfrom(1024)[0])['name'], 'Example Changed Server')
            finally:
                responder.stop()
            self.assertFalse(responder.is_alive())

    def test_toggle_starts_once_and_stops_immediately(self):
        shop = {'discovery_enabled': False}
        with patch.object(discovery, 'load_settings', return_value={'shop': shop}), \
             patch.object(discovery, '_server_uid', return_value='fixture-id') as uid, \
             patch.object(discovery, 'DiscoveryResponder') as factory:
            discovery.reconcile(http_port=8123)
            factory.assert_not_called()
            uid.assert_not_called()
            shop['discovery_enabled'] = True
            discovery.reconcile()
            discovery.reconcile()
            factory.assert_called_once_with('fixture-id', 8123)
            factory.return_value.bind.assert_called_once()
            factory.return_value.start.assert_called_once()
            shop['discovery_enabled'] = False
            discovery.reconcile()
            factory.return_value.stop.assert_called_once()
            self.assertIsNone(discovery._responder)

    def _settings_route(self, valid=True):
        # Exercise the actual route without starting the database and scheduler.
        tree = ast.parse(Path('app/app.py').read_text(encoding='utf-8'))
        route = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == 'set_shop_settings_api')
        route.decorator_list = []
        calls = Mock()
        context = {
            'request': SimpleNamespace(json={'discovery_enabled': True}),
            'load_settings': Mock(return_value={'shop': {}}),
            'verify_settings': Mock(return_value=(valid, [])),
            'set_shop_settings': calls.save,
            'discovery': SimpleNamespace(reconcile=calls.reconcile),
            'set_security_settings': calls.security,
            'reload_conf': calls.reload,
            '_invalidate_shop_root_cache': calls.invalidate,
            'jsonify': lambda value: value,
        }
        exec(compile(ast.Module(body=[route], type_ignores=[]), '<settings route>', 'exec'), context)
        return context['set_shop_settings_api'], calls

    def test_settings_route_reconciles_after_persisting_toggle(self):
        route, calls = self._settings_route()
        self.assertTrue(route()['success'])
        calls.save.assert_called_once_with({'discovery_enabled': True, 'host': ''})
        self.assertEqual([c[0] for c in calls.mock_calls], ['save', 'reconcile', 'reload', 'invalidate'])

    def test_invalid_settings_do_not_change_discovery(self):
        route, calls = self._settings_route(valid=False)
        self.assertEqual(route()[1], 400)
        self.assertEqual(calls.mock_calls, [])

    def test_bind_failure_does_not_break_application_and_can_retry(self):
        with patch.object(discovery, 'load_settings', return_value={'shop': {'discovery_enabled': True}}), \
             patch.object(discovery, '_server_uid', return_value='fixture-id'), \
             patch.object(discovery, 'DiscoveryResponder') as factory:
            factory.return_value.bind.side_effect = OSError('fixture occupied port')
            with self.assertLogs('main', level='WARNING'):
                discovery.reconcile()
            self.assertIsNone(discovery._responder)
            factory.return_value.bind.side_effect = None
            discovery.reconcile()
            self.assertIsNotNone(discovery._responder)


if __name__ == '__main__':
    unittest.main()
