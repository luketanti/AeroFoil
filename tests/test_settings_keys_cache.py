import hashlib
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from app import settings


class FakeKeys:
    keys_loaded = None
    _loaded_checksum = None
    _loaded_revisions = []
    _incorrect_revisions = []
    load_calls = 0

    @classmethod
    def reset(cls):
        cls.keys_loaded = None
        cls._loaded_checksum = None
        cls._loaded_revisions = []
        cls._incorrect_revisions = []
        cls.load_calls = 0

    @classmethod
    def load(cls, file_name):
        cls.load_calls += 1
        with open(file_name, 'rb') as handle:
            cls._loaded_checksum = hashlib.sha256(handle.read()).hexdigest()
        # Simulate partially valid keys: load() false, but at least one revision loaded.
        cls.keys_loaded = False
        cls._loaded_revisions = ['master_key_14']
        cls._incorrect_revisions = []
        return cls.keys_loaded

    @classmethod
    def getLoadedKeysChecksum(cls):
        return cls._loaded_checksum

    @classmethod
    def getLoadedKeysRevisions(cls):
        return list(cls._loaded_revisions)

    @classmethod
    def getIncorrectKeysRevisions(cls):
        return list(cls._incorrect_revisions)


class SettingsKeysCacheTests(unittest.TestCase):
    def setUp(self):
        FakeKeys.reset()
        settings._keys_validation_cache.clear()

        self.nsz_module = types.ModuleType('nsz')
        self.nsz_nut_module = types.ModuleType('nsz.nut')
        self.nsz_nut_module.Keys = FakeKeys
        self.nsz_module.nut = self.nsz_nut_module
        self.patcher = patch.dict(
            sys.modules,
            {
                'nsz': self.nsz_module,
                'nsz.nut': self.nsz_nut_module,
            }
        )
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def _write_temp_keys_file(self, data):
        fd, path = tempfile.mkstemp(prefix='ownfoil_keys_', suffix='.txt')
        os.close(fd)
        with open(path, 'wb') as handle:
            handle.write(data)
        return path

    def test_validate_keys_file_uses_cache_for_same_checksum(self):
        path = self._write_temp_keys_file(b'master_key_14 = 00112233445566778899AABBCCDDEEFF\n')
        try:
            valid_a, errors_a = settings.validate_keys_file(path)
            valid_b, errors_b = settings.validate_keys_file(path)
        finally:
            os.remove(path)

        self.assertTrue(valid_a)
        self.assertTrue(valid_b)
        self.assertEqual(errors_a, [])
        self.assertEqual(errors_b, [])
        self.assertEqual(FakeKeys.load_calls, 1)

    def test_validate_keys_file_reloads_when_checksum_changes(self):
        path = self._write_temp_keys_file(b'master_key_14 = 00112233445566778899AABBCCDDEEFF\n')
        try:
            settings.validate_keys_file(path)
            with open(path, 'wb') as handle:
                handle.write(b'master_key_14 = FFEEDDCCBBAA99887766554433221100\n')
            settings.validate_keys_file(path)
        finally:
            os.remove(path)

        self.assertEqual(FakeKeys.load_calls, 2)


if __name__ == '__main__':
    unittest.main()
