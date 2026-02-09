import os
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

if "unzip_http" not in sys.modules:
    sys.modules["unzip_http"] = types.SimpleNamespace(RemoteZipFile=object)

from app import titledb
from app import titles


class TitleDBResilienceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = self._tmp.name
        self.titledb_dir = os.path.join(self.tmp_root, "titledb")
        os.makedirs(self.titledb_dir, exist_ok=True)
        self.settings = {"titles": {"region": "US", "language": "en"}}
        titles._reset_titledb_state()
        titles.identification_in_progress_count = 0
        titles._missing_files_recovery_last_attempt_ts = 0.0
        titles._missing_files_recovery_in_progress = False
        titles._titledb_data_signature = None

    def tearDown(self):
        titles._reset_titledb_state()
        titles.identification_in_progress_count = 0
        titles._missing_files_recovery_last_attempt_ts = 0.0
        titles._missing_files_recovery_in_progress = False
        titles._titledb_data_signature = None
        self._tmp.cleanup()

    def _write_core_files(self, region_content):
        with open(os.path.join(self.titledb_dir, "cnmts.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "titles.US.en.json"), "w", encoding="utf-8") as fp:
            fp.write(region_content)
        with open(os.path.join(self.titledb_dir, "versions.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.txt"), "w", encoding="utf-8") as fp:
            fp.write("0100000000001000|ignored|0\n")

    def test_load_titledb_returns_false_when_recovery_raises(self):
        self._write_core_files('{"broken":')

        with patch.object(titles, "TITLEDB_DIR", self.titledb_dir), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"), \
            patch("app.titles.titledb.update_titledb", side_effect=RuntimeError("network down")) as mocked_update:
            loaded = titles.load_titledb()

        self.assertFalse(loaded)
        self.assertEqual(mocked_update.call_count, 1)

    def test_load_titledb_returns_false_when_recovery_does_not_fix_file(self):
        self._write_core_files('{"broken":')

        with patch.object(titles, "TITLEDB_DIR", self.titledb_dir), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"), \
            patch("app.titles.titledb.update_titledb", return_value=None) as mocked_update:
            loaded = titles.load_titledb()

        self.assertFalse(loaded)
        self.assertEqual(mocked_update.call_count, 1)

    def test_load_titledb_recovers_missing_region_file(self):
        with open(os.path.join(self.titledb_dir, "cnmts.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.txt"), "w", encoding="utf-8") as fp:
            fp.write("0100000000001000|ignored|0\n")

        region_path = os.path.join(self.titledb_dir, "titles.US.en.json")

        def _recover_missing(_settings):
            with open(region_path, "w", encoding="utf-8") as fp:
                fp.write('{"key":{"id":"0100000000001000","name":"Game","bannerUrl":"","iconUrl":"","category":""}}')
            recovered.set()

        recovered = threading.Event()
        with patch.object(titles, "TITLEDB_DIR", self.titledb_dir), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"), \
            patch("app.titles.titledb.get_descriptions_url", return_value=("https://example.invalid/US.en.json", "US.en.json")), \
            patch("app.titles._ensure_titledb_descriptions_file", return_value=None), \
            patch("app.titles.titledb.update_titledb", side_effect=_recover_missing) as mocked_update:
            first_load = titles.load_titledb()
            recovered.wait(timeout=2)
            second_load = titles.load_titledb()

        self.assertFalse(first_load)
        self.assertTrue(second_load)
        self.assertEqual(mocked_update.call_count, 1)
        titles.release_titledb()

    def test_load_titledb_missing_files_respects_recovery_cooldown(self):
        with open(os.path.join(self.titledb_dir, "cnmts.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.txt"), "w", encoding="utf-8") as fp:
            fp.write("0100000000001000|ignored|0\n")

        with patch.object(titles, "TITLEDB_DIR", self.titledb_dir), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"), \
            patch("app.titles.titledb.update_titledb", return_value=None) as mocked_update:
            first_load = titles.load_titledb()
            # Allow recovery thread to complete and update cooldown timestamp.
            for _ in range(20):
                if mocked_update.call_count:
                    break
                threading.Event().wait(0.01)
            second_load = titles.load_titledb()

        self.assertFalse(first_load)
        self.assertFalse(second_load)
        self.assertEqual(mocked_update.call_count, 1)

    def test_download_titledb_files_keeps_old_file_when_new_json_invalid(self):
        old_content = '{"ok": true}'
        target_path = os.path.join(self.titledb_dir, "titles.US.en.json")
        with open(target_path, "w", encoding="utf-8") as fp:
            fp.write(old_content)

        def _write_invalid(_rzf, _path, store_path):
            with open(store_path, "w", encoding="utf-8") as fp:
                fp.write('{"broken":')

        with patch.object(titledb, "TITLEDB_DIR", self.titledb_dir), \
            patch.object(titledb, "APP_DIR", self.tmp_root), \
            patch("app.titledb.download_from_remote_zip", side_effect=_write_invalid):
            with self.assertRaises(ValueError):
                titledb.download_titledb_files(object(), ["titles.US.en.json"])

        with open(target_path, "r", encoding="utf-8") as fp:
            self.assertEqual(fp.read(), old_content)
        self.assertFalse(os.path.exists(target_path + ".tmp"))

    def test_titledb_cache_token_updates_after_successful_load(self):
        self._write_core_files('{"key":{"id":"0100000000001000","name":"Game","bannerUrl":"","iconUrl":"","category":""}}')
        before = titles.get_titledb_cache_token()
        self.assertTrue(before.startswith("missing"))

        with patch.object(titles, "TITLEDB_DIR", self.titledb_dir), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"), \
            patch("app.titles.titledb.get_descriptions_url", return_value=("https://example.invalid/US.en.json", "US.en.json")), \
            patch("app.titles._ensure_titledb_descriptions_file", return_value=None):
            loaded = titles.load_titledb()

        self.assertTrue(loaded)
        after = titles.get_titledb_cache_token()
        self.assertNotEqual(before, after)
        self.assertNotIn("missing", after)
        titles.release_titledb()


if __name__ == "__main__":
    unittest.main()
