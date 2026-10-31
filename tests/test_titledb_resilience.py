import os
import shutil
import sys
import threading
import types
import unittest
import uuid
from contextlib import ExitStack
from unittest.mock import patch

if "unzip_http" not in sys.modules:
    sys.modules["unzip_http"] = types.SimpleNamespace(RemoteZipFile=object)

from app import titledb
from app import titles


class TitleDBResilienceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = None
        self._tmp_root_parent = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".tmp", "titledb-tests"))
        os.makedirs(self._tmp_root_parent, exist_ok=True)
        self.tmp_root = os.path.join(self._tmp_root_parent, f"case-{uuid.uuid4().hex}")
        os.makedirs(self.tmp_root, exist_ok=False)
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
        shutil.rmtree(self.tmp_root, ignore_errors=True)

    def _write_core_files(self, region_content):
        with open(os.path.join(self.titledb_dir, "cnmts.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "titles.US.en.json"), "w", encoding="utf-8") as fp:
            fp.write(region_content)
        with open(os.path.join(self.titledb_dir, "versions.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.txt"), "w", encoding="utf-8") as fp:
            fp.write("0100000000001000|ignored|0\n")
        with open(os.path.join(self.titledb_dir, "languages.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")

    class _FakeRemoteZip:
        def __init__(self, filenames):
            self._filenames = list(filenames)

        class _Info:
            def __init__(self, filename):
                self.filename = filename

        def infolist(self):
            return [TitleDBResilienceTests._FakeRemoteZip._Info(name) for name in self._filenames]

    def _patch_titles_env(self):
        stack = ExitStack()
        stack.enter_context(patch.object(titles, "TITLEDB_DIR", self.titledb_dir))
        stack.enter_context(patch.object(titles, "APP_DIR", self.tmp_root))
        stack.enter_context(patch.object(titles, "_versions_index_file", os.path.join(self.titledb_dir, "versions.index.sqlite3")))
        stack.enter_context(patch.object(titles, "_cnmts_default_index_file", os.path.join(self.titledb_dir, "cnmts.index.sqlite3")))
        stack.enter_context(patch.object(titles, "_cnmts_fixed_index_file", os.path.join(self.titledb_dir, "cnmts-fixed.index.sqlite3")))
        stack.enter_context(patch.object(titles, "_cnmts_index_file", os.path.join(self.titledb_dir, "cnmts.index.sqlite3")))
        stack.enter_context(patch.object(titles, "_titles_index_file", os.path.join(self.titledb_dir, "titles.index.sqlite3")))
        stack.enter_context(patch("app.titles._ensure_versions_index", side_effect=self._fake_ensure_versions_index))
        stack.enter_context(patch("app.titles._ensure_cnmts_index", side_effect=self._fake_ensure_cnmts_index))
        stack.enter_context(patch("app.titles._ensure_titles_index", side_effect=self._fake_ensure_titles_index))
        return stack

    def _fake_ensure_versions_index(self, versions_file):
        data = titles._load_json_file(versions_file, "versions")
        if not isinstance(data, dict):
            raise ValueError("Invalid versions.json structure: expected object at root")
        titles._versions_index_ready = True
        return True

    def _fake_ensure_cnmts_index(self, cnmts_file):
        data = titles._load_json_file(cnmts_file, "cnmts")
        if not isinstance(data, dict):
            raise ValueError("Invalid cnmts.json structure: expected object at root")
        titles._cnmts_index_ready = True
        return True

    def _fake_ensure_titles_index(self, region_titles_file):
        data = titles._load_json_file(region_titles_file, "region_titles")
        if not isinstance(data, dict):
            raise ValueError("Invalid region titles file: expected object at root")
        titles._titles_index_ready = True
        return True

    def test_load_titledb_returns_false_when_recovery_raises(self):
        self._write_core_files('{"broken":')

        with self._patch_titles_env(), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"), \
            patch("app.titles.titledb.update_titledb", side_effect=RuntimeError("network down")) as mocked_update:
            loaded = titles.load_titledb()

        self.assertFalse(loaded)
        self.assertEqual(mocked_update.call_count, 1)

    def test_load_titledb_returns_false_when_recovery_does_not_fix_file(self):
        self._write_core_files('{"broken":')

        with self._patch_titles_env(), \
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
        with self._patch_titles_env(), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"), \
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

        with self._patch_titles_env(), \
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

        with patch.object(titledb, "TITLEDB_DIR", self.titledb_dir), \
            patch.object(titledb, "APP_DIR", self.tmp_root), \
            patch("app.titledb.download_from_remote_zip", return_value=None), \
            patch("app.titledb._validate_downloaded_titledb_file", return_value=False), \
            patch("app.titledb._remove_temp_file") as mocked_cleanup:
            with self.assertRaises(ValueError):
                titledb.download_titledb_files(object(), ["titles.US.en.json"])

        with open(target_path, "r", encoding="utf-8") as fp:
            self.assertEqual(fp.read(), old_content)
        mocked_cleanup.assert_called_once_with(target_path + ".tmp")

    def test_titledb_cache_token_updates_after_successful_load(self):
        self._write_core_files('{"key":{"id":"0100000000001000","name":"Game","bannerUrl":"","iconUrl":"","category":""}}')
        before = titles.get_titledb_cache_token()
        self.assertTrue(before.startswith("missing"))

        with self._patch_titles_env(), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"):
            loaded = titles.load_titledb()

        self.assertTrue(loaded)
        after = titles.get_titledb_cache_token()
        self.assertNotEqual(before, after)
        self.assertNotIn("missing", after)
        titles.release_titledb()

    def test_load_titledb_reloads_when_signature_changes(self):
        self._write_core_files('{"key":{"id":"0100000000001000","name":"Game v1","bannerUrl":"","iconUrl":"","category":""}}')

        with self._patch_titles_env(), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"), \
            patch("app.titles._build_titledb_data_signature", side_effect=["sig-v1", "sig-v2", "sig-v2"]):
            first_loaded = titles.load_titledb()
            self.assertTrue(first_loaded)
            titles.release_titledb()

            with patch("app.titles._ensure_titles_index", wraps=titles._ensure_titles_index) as ensure_titles_index_mock:
                second_loaded = titles.load_titledb()

            self.assertTrue(second_loaded)
            self.assertGreaterEqual(ensure_titles_index_mock.call_count, 1)

        titles.release_titledb()

    def test_required_titledb_files_prefers_fixed_cnmts_when_present(self):
        self._write_core_files('{"0100000000001000":{"id":"0100000000001000","name":"Example Title","bannerUrl":"","iconUrl":"","category":""}}')
        fixed_path = os.path.join(self.titledb_dir, "cnmts-fixed.json")
        with open(fixed_path, "w", encoding="utf-8") as fp:
            fp.write("{}")

        with patch.object(titles, "TITLEDB_DIR", self.titledb_dir), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"):
            required = dict(titles._required_titledb_files(self.settings))

        self.assertEqual(required["cnmts"], fixed_path)

    def test_load_titledb_uses_fixed_cnmts_index_when_fixed_file_present(self):
        self._write_core_files('{"0100000000001000":{"id":"0100000000001000","name":"Example Title","bannerUrl":"","iconUrl":"","category":""}}')
        fixed_path = os.path.join(self.titledb_dir, "cnmts-fixed.json")
        fixed_index_path = os.path.join(self.titledb_dir, "cnmts-fixed.index.sqlite3")
        with open(fixed_path, "w", encoding="utf-8") as fp:
            fp.write("{}")

        with self._patch_titles_env(), \
            patch("app.titles.load_settings", return_value=self.settings), \
            patch("app.titles.titledb.get_region_titles_file", return_value="titles.US.en.json"):
            loaded = titles.load_titledb()
            self.assertEqual(titles._cnmts_index_file, fixed_index_path)

        self.assertTrue(loaded)
        titles.release_titledb()

    def test_update_titledb_files_downloads_missing_optional_fixed_file_without_new_commit(self):
        latest_marker = "latest_example123"
        local_latest = os.path.join(self.titledb_dir, ".latest")
        with open(local_latest, "w", encoding="utf-8") as fp:
            fp.write("example123")
        with open(os.path.join(self.titledb_dir, "cnmts.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "titles.US.en.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.txt"), "w", encoding="utf-8") as fp:
            fp.write("0100000000001000|ignored|0\n")
        with open(os.path.join(self.titledb_dir, "languages.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")

        fake_zip = self._FakeRemoteZip([
            latest_marker,
            "cnmts.json",
            "cnmts-fixed.json",
            "versions.json",
            "versions.txt",
            "languages.json",
            "titles.US.en.json",
        ])

        with patch.object(titledb, "TITLEDB_DIR", self.titledb_dir), \
            patch.object(titledb, "APP_DIR", self.tmp_root), \
            patch.object(titledb, "TITLEDB_ARTEFACTS_URL", "https://example.invalid/titledb.zip"), \
            patch("app.titledb._get_with_retry", return_value=types.SimpleNamespace(status_code=302, headers={"Location": "https://example.invalid/direct.zip"})), \
            patch("app.titledb.unzip_http.RemoteZipFile", return_value=fake_zip), \
            patch("app.titledb.download_titledb_files") as mocked_download:
            titledb.update_titledb_files(self.settings)

        mocked_download.assert_called_once_with(fake_zip, ["cnmts-fixed.json"])

    def test_update_titledb_files_downloads_english_title_sources_when_enabled(self):
        latest_marker = "latest_example123"
        local_latest = os.path.join(self.titledb_dir, ".latest")
        with open(local_latest, "w", encoding="utf-8") as fp:
            fp.write("example123")
        with open(os.path.join(self.titledb_dir, "cnmts.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "titles.JP.ja.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")
        with open(os.path.join(self.titledb_dir, "versions.txt"), "w", encoding="utf-8") as fp:
            fp.write("0100000000001000|ignored|0\n")
        with open(os.path.join(self.titledb_dir, "languages.json"), "w", encoding="utf-8") as fp:
            fp.write("{}")

        settings_with_english = {"titles": {"region": "JP", "language": "ja", "prefer_english_metadata": True}}
        fake_zip = self._FakeRemoteZip([
            latest_marker,
            "cnmts.json",
            "versions.json",
            "versions.txt",
            "languages.json",
            "titles.JP.ja.json",
            "titles.JP.en.json",
            "titles.US.en.json",
            "titles.GB.en.json",
        ])

        with patch.object(titledb, "TITLEDB_DIR", self.titledb_dir), \
            patch.object(titledb, "APP_DIR", self.tmp_root), \
            patch.object(titledb, "TITLEDB_ARTEFACTS_URL", "https://example.invalid/titledb.zip"), \
            patch("app.titledb._get_with_retry", return_value=types.SimpleNamespace(status_code=302, headers={"Location": "https://example.invalid/direct.zip"})), \
            patch("app.titledb.unzip_http.RemoteZipFile", return_value=fake_zip), \
            patch("app.titledb.download_titledb_files") as mocked_download:
            titledb.update_titledb_files(settings_with_english)

        mocked_download.assert_called_once_with(
            fake_zip,
            [
                "titles.JP.en.json",
                "titles.US.en.json",
                "titles.GB.en.json",
            ],
        )


if __name__ == "__main__":
    unittest.main()
