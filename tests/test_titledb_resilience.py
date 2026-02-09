import os
import sys
import tempfile
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

    def tearDown(self):
        titles._reset_titledb_state()
        titles.identification_in_progress_count = 0
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


if __name__ == "__main__":
    unittest.main()
