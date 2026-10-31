import os
import re
import shutil
import unittest
from collections import namedtuple
from types import SimpleNamespace
from unittest.mock import patch

TEST_TMP_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".tmp")


def _normalize_fixture_path(value):
    text = str(value or "")
    if re.match(r"^[A-Za-z]:[\\/]", text) or "\\" in text:
        return text.replace("/", "\\")
    return os.path.normpath(text)

_IMPORT_ERROR = None
flask_app = None
try:
    from app.app import app as flask_app
    from app.app import _app_has_deletable_files
    from app.app import _build_library_download_files
    from app.app import _build_title_details_dlc_items
    from app.app import _build_deletable_version_map
    from app.app import _sort_library_rows_by_title_name
    from app.app import manage_delete_library_content
    from app.library import (
        _build_staging_output_path,
        _cleanup_import_staging_roots,
        _delete_target_apps,
        _finalize_staged_conversion_output,
        _format_nsz_command,
        _is_hardlinked_file,
        _iter_library_files,
        _parse_command_args,
        _pending_cleanup_roots,
        _pending_organize_paths,
        _sanitize_component,
        delete_duplicates,
        delete_older_updates,
        delete_library_content,
        delete_orphaned_addons,
        enqueue_cleanup_roots,
        enqueue_organize_paths,
        generate_library,
    )
    from app.titles import getDirsAndFiles
except ModuleNotFoundError as exc:
    _IMPORT_ERROR = exc


class LibraryHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _IMPORT_ERROR is not None:
            raise unittest.SkipTest(f"Missing dependency for library helper tests: {_IMPORT_ERROR}")

    class _InvertibleExpr:
        def __invert__(self):
            return self

    class _AdminUser:
        is_authenticated = True

        @staticmethod
        def has_access(access):
            return access == "admin"

    @staticmethod
    def _make_app(app_pk, app_id, app_type, version):
        return SimpleNamespace(
            id=app_pk,
            app_id=app_id,
            app_type=app_type,
            app_version=str(version),
            files=[],
        )

    @staticmethod
    def _make_file(file_id, filepath, linked_apps):
        return SimpleNamespace(
            id=file_id,
            filepath=filepath,
            apps=list(linked_apps),
        )

    @patch('app.library.os.stat')
    def test_hardlinked_file_detection_uses_link_count(self, stat_mock):
        stat_mock.return_value = SimpleNamespace(st_nlink=2)

        self.assertTrue(_is_hardlinked_file('X:\\fixture-root\\Example Title.nsp'))

        stat_mock.return_value = SimpleNamespace(st_nlink=1)
        self.assertFalse(_is_hardlinked_file('X:\\fixture-root\\Example Title.nsp'))

    @patch('app.library.os.stat', side_effect=OSError('unavailable'))
    def test_hardlinked_file_detection_tolerates_stat_failure(self, stat_mock):
        self.assertFalse(_is_hardlinked_file('X:\\fixture-root\\Example Title.nsp'))

    @patch('app.app.os.path.isfile')
    def test_build_library_download_files_exposes_existing_files_only(self, isfile_mock):
        isfile_mock.side_effect = lambda path: path == 'X:\\fixture-root\\Example Base.nsp'
        app_entry = SimpleNamespace(files=[
            SimpleNamespace(
                id=7,
                filepath='X:\\fixture-root\\Example Base.nsp',
                filename='Example Base.nsp',
                size=123,
            ),
            SimpleNamespace(
                id=8,
                filepath='X:\\fixture-root\\missing.nsp',
                filename='missing.nsp',
                size=456,
            ),
        ])

        files = _build_library_download_files(app_entry)

        self.assertEqual(files, [{
            'id': 7,
            'filename': 'Example Base.nsp',
            'size': 123,
            'url': '/api/get_game/7?download=1',
        }])

    def _make_test_temp_root(self, name):
        os.makedirs(TEST_TMP_ROOT, exist_ok=True)
        tmp_root = os.path.join(TEST_TMP_ROOT, name)
        shutil.rmtree(tmp_root, ignore_errors=True)
        os.makedirs(tmp_root, exist_ok=True)
        self.addCleanup(shutil.rmtree, tmp_root, ignore_errors=True)
        return tmp_root

    def test_sort_library_rows_by_title_name_uses_visible_title_names(self):
        row_type = namedtuple("LibraryRow", ["title_id", "app_id"])
        rows = [
            row_type(title_id="0100BBBB00000000", app_id="0100BBBB00000000"),
            row_type(title_id="0100AAAA00000000", app_id="0100AAAA00000000"),
            row_type(title_id="0100CCCC00000000", app_id="0100CCCC00000000"),
        ]
        title_name_map = {
            "0100AAAA00000000": "example title z",
            "0100BBBB00000000": "example title m",
            "0100CCCC00000000": "example title a",
        }

        asc_rows = _sort_library_rows_by_title_name(rows, title_name_map, descending=False)
        desc_rows = _sort_library_rows_by_title_name(rows, title_name_map, descending=True)

        self.assertEqual(
            [row.title_id for row in asc_rows],
            ["0100CCCC00000000", "0100BBBB00000000", "0100AAAA00000000"],
        )
        self.assertEqual(
            [row.title_id for row in desc_rows],
            ["0100AAAA00000000", "0100BBBB00000000", "0100CCCC00000000"],
        )

    @patch("app.library.get_library_cache_state_token", return_value="state-token")
    @patch("app.library.save_library_to_disk")
    @patch("app.library.titles_lib.get_game_info")
    @patch("app.library.get_all_apps")
    @patch("app.library.is_library_unchanged", return_value=False)
    @patch("app.library.titles_lib.titledb_session")
    @patch("app.library.db.session.query")
    def test_generate_library_includes_files_in_cached_rows(
        self,
        db_query_mock,
        titledb_session_mock,
        is_library_unchanged_mock,
        get_all_apps_mock,
        get_game_info_mock,
        save_library_to_disk_mock,
        get_state_token_mock,
    ):
        app_file = SimpleNamespace(
            filepath="X:\\fixture-root\\Example Release NSW-GRP\\Example.nsp",
            filename="Example.nsp",
            folder="\\Example Release NSW-GRP",
            size=12345,
        )
        app_obj = SimpleNamespace(
            app_id="0100AAAA00000000",
            app_version="0",
            files=[app_file],
        )

        class _AppsQuery:
            def options(self, *_args, **_kwargs):
                return self

            def filter(self, *_args, **_kwargs):
                return self

            def all(self):
                return [app_obj]

        class _TitlesQuery:
            def all(self):
                return []

        def _query_side_effect(*args, **kwargs):
            if args and getattr(args[0], "__name__", "") == "Apps":
                return _AppsQuery()
            return _TitlesQuery()

        db_query_mock.side_effect = _query_side_effect
        titledb_session_mock.return_value.__enter__.return_value = None
        titledb_session_mock.return_value.__exit__.return_value = False
        get_all_apps_mock.return_value = [{
            "id": 1,
            "title_db_id": 1,
            "title_id": "0100AAAA00000000",
            "app_id": "0100AAAA00000000",
            "app_version": "0",
            "app_type": "BASE",
            "owned": True,
            "size": 12345,
        }]
        get_game_info_mock.return_value = {
            "name": "Example Title",
            "category": "Action",
        }

        library = generate_library()

        self.assertEqual(len(library), 1)
        self.assertIn("files", library[0])
        self.assertEqual(len(library[0]["files"]), 1)
        self.assertEqual(
            library[0]["files"][0]["filename"],
            "Example.nsp",
        )
        saved_payload = save_library_to_disk_mock.call_args[0][0]
        self.assertEqual(saved_payload["version"], 8)
        self.assertIn("files", saved_payload["library"][0])

    def test_sanitize_component(self):
        self.assertEqual(_sanitize_component('Game: Name?'), 'Game Name')
        self.assertEqual(_sanitize_component(''), 'Unknown')

    def test_format_nsz_command_threads(self):
        command = _format_nsz_command(
            '{nsz_runner} -C -o "{output_dir}" "{input_file}"',
            'C:\\input.nsp',
            'C:\\output.nsz',
            threads=4
        )
        self.assertIn('-t 4', command)
        self.assertIn('input.nsp', command)

    def test_parse_command_args_strips_windows_wrapping_quotes(self):
        command = (
            '"C:\\Program Files\\Python\\python.exe" '
            '-c "import nsz; nsz.main()" '
            '--keys "C:\\AeroFoil\\keys.txt" '
            '"C:\\Library\\Example Title.nsp"'
        )

        with patch('app.library.os.name', 'nt'):
            args = _parse_command_args(command)

        self.assertEqual(
            args,
            [
                'C:\\Program Files\\Python\\python.exe',
                '-c',
                'import nsz; nsz.main()',
                '--keys',
                'C:\\AeroFoil\\keys.txt',
                'C:\\Library\\Example Title.nsp',
            ],
        )

    def test_build_staging_output_path_disabled_returns_final_output(self):
        source = '/library/Game.nsp'
        output = '/library/Game.nsz'
        self.assertEqual(_build_staging_output_path(source, output, ''), output)

    def test_build_staging_output_path_uses_staging_root(self):
        source = '/library/Game.nsp'
        output = '/library/Game.nsz'
        staging = os.path.join(TEST_TMP_ROOT, 'aerofoil-stage')
        staged_output = _build_staging_output_path(source, output, staging)
        self.assertTrue(staged_output.startswith(staging + os.sep))
        self.assertEqual(os.path.basename(staged_output), 'Game.nsz')

    @patch("app.library._resolve_existing_output_path", return_value=None)
    @patch("app.library._cleanup_empty_parent_dirs")
    @patch("app.library.shutil.move")
    def test_finalize_staged_conversion_output_moves_file_to_source_directory(
        self,
        move_mock,
        cleanup_mock,
        existing_output_mock,
    ):
        tmp_root = self._make_test_temp_root('aerofoil_finalize')

        library_dir = os.path.join(tmp_root, 'library')
        staging_root = os.path.join(tmp_root, 'staging')
        os.makedirs(library_dir, exist_ok=True)
        os.makedirs(staging_root, exist_ok=True)

        source_path = os.path.join(library_dir, 'Sample.nsp')
        staged_dir = os.path.join(staging_root, 'run-1')
        os.makedirs(staged_dir, exist_ok=True)
        staged_output = os.path.join(staged_dir, 'Sample.nsz')
        with open(staged_output, 'wb') as handle:
            handle.write(b'nsz-output')

        final_output = _finalize_staged_conversion_output(
            source_path=source_path,
            staged_output_path=staged_output,
            staging_root=staging_root,
        )

        self.assertEqual(final_output, os.path.join(library_dir, 'Sample.nsz'))
        move_mock.assert_called_once_with(staged_output, final_output)
        cleanup_mock.assert_called_once_with(os.path.dirname(staged_output), staging_root)

    def test_finalize_staged_conversion_output_fails_if_final_exists(self):
        tmp_root = self._make_test_temp_root('aerofoil_finalize_exists')

        library_dir = os.path.join(tmp_root, 'library')
        staging_root = os.path.join(tmp_root, 'staging')
        os.makedirs(library_dir, exist_ok=True)
        os.makedirs(staging_root, exist_ok=True)

        source_path = os.path.join(library_dir, 'Sample.nsp')
        existing_final = os.path.join(library_dir, 'Sample.nsz')
        with open(existing_final, 'wb') as handle:
            handle.write(b'existing')

        staged_output = os.path.join(staging_root, 'Sample.nsz')
        with open(staged_output, 'wb') as handle:
            handle.write(b'new-output')

        with self.assertRaises(FileExistsError):
            _finalize_staged_conversion_output(
                source_path=source_path,
                staged_output_path=staged_output,
                staging_root=staging_root,
            )

    @patch("app.library.os.walk")
    @patch("app.library.os.path.isdir", return_value=True)
    @patch("app.library.os.path.isfile", return_value=False)
    def test_enqueue_organize_paths_expands_directories_to_files(self, isfile_mock, isdir_mock, walk_mock):
        walk_mock.return_value = [
            ("X:\\fixture-root\\Example Release NSW-GRP", [], ["game.nsp", "readme.nfo"]),
            ("X:\\fixture-root\\Example Release NSW-GRP\\subdir", [], ["dlc.nsp"]),
        ]
        _pending_organize_paths.clear()
        try:
            enqueue_organize_paths(["X:\\fixture-root\\Example Release NSW-GRP"])
            self.assertEqual({_normalize_fixture_path(path) for path in _pending_organize_paths}, {
                "X:\\fixture-root\\Example Release NSW-GRP\\game.nsp",
                "X:\\fixture-root\\Example Release NSW-GRP\\readme.nfo",
                "X:\\fixture-root\\Example Release NSW-GRP\\subdir\\dlc.nsp",
            })
        finally:
            _pending_organize_paths.clear()

    @patch("app.library.os.path.isdir", return_value=True)
    def test_enqueue_cleanup_roots_tracks_only_directories(self, isdir_mock):
        _pending_cleanup_roots.clear()
        try:
            enqueue_cleanup_roots(["X:\\fixture-root\\Example Release NSW-GRP"])
            self.assertEqual(_pending_cleanup_roots, {"X:\\fixture-root\\Example Release NSW-GRP"})
        finally:
            _pending_cleanup_roots.clear()

    @patch("app.library.os.rmdir")
    @patch("app.library.os.listdir", return_value=[])
    @patch("app.library.os.remove")
    @patch("app.library.os.walk")
    @patch("app.library.os.path.isdir", return_value=True)
    def test_cleanup_import_staging_roots_removes_only_unsupported_leftovers(
        self,
        isdir_mock,
        walk_mock,
        remove_mock,
        listdir_mock,
        rmdir_mock,
    ):
        walk_mock.return_value = [
            ("X:\\fixture-root\\Example Release NSW-GRP\\subdir", [], ["keep.nsp", "keep-dlc.nsp.hdf", "proof.nfo"]),
            ("X:\\fixture-root\\Example Release NSW-GRP", ["subdir"], ["notes.txt"]),
        ]

        _cleanup_import_staging_roots(["X:\\fixture-root\\Example Release NSW-GRP"])

        self.assertEqual(
            [_normalize_fixture_path(call.args[0]) for call in remove_mock.call_args_list],
            [
                "X:\\fixture-root\\Example Release NSW-GRP\\subdir\\proof.nfo",
                "X:\\fixture-root\\Example Release NSW-GRP\\notes.txt",
            ],
        )

    def test_iter_library_files_includes_wrapped_supported_files(self):
        tmp_root = self._make_test_temp_root("iter_library_files")
        os.makedirs(os.path.join(tmp_root, "subdir"), exist_ok=True)
        with open(os.path.join(tmp_root, "base.nsp.hdf"), "w", encoding="utf-8") as handle:
            handle.write("wrapped")
        with open(os.path.join(tmp_root, "subdir", "update.nsz"), "w", encoding="utf-8") as handle:
            handle.write("native")
        with open(os.path.join(tmp_root, "subdir", "notes.txt"), "w", encoding="utf-8") as handle:
            handle.write("ignored")

        result = sorted(os.path.relpath(path, tmp_root) for path in _iter_library_files(tmp_root))

        self.assertEqual(
            result,
            [
                "base.nsp.hdf",
                os.path.join("subdir", "update.nsz"),
            ],
        )

    def test_get_dirs_and_files_includes_wrapped_supported_files(self):
        tmp_root = self._make_test_temp_root("get_dirs_and_files")
        os.makedirs(os.path.join(tmp_root, "nested"), exist_ok=True)
        with open(os.path.join(tmp_root, "nested", "dlc.nsp.hdf"), "w", encoding="utf-8") as handle:
            handle.write("wrapped")
        with open(os.path.join(tmp_root, "nested", "proof.nfo"), "w", encoding="utf-8") as handle:
            handle.write("ignored")

        dirs, files = getDirsAndFiles(tmp_root)

        self.assertIn(os.path.join(tmp_root, "nested"), dirs)
        self.assertEqual(files, [os.path.join(tmp_root, "nested", "dlc.nsp.hdf")])

    @patch("app.library.delete_file_by_filepath")
    @patch("app.library.os.remove")
    @patch("app.library.os.path.exists", return_value=True)
    def test_delete_target_apps_skips_shared_files_linked_to_non_target_apps(
        self,
        exists_mock,
        remove_mock,
        delete_file_mock,
    ):
        target_app = self._make_app(1, "0100AAAA", "UPDATE", 1)
        foreign_app = self._make_app(2, "0100BBBB", "DLC", 0)
        file_entry = self._make_file(101, "X:\\library\\shared.nsp", [target_app, foreign_app])
        target_app.files = [file_entry]

        result = _delete_target_apps([target_app], dry_run=False, verbose=True)

        self.assertTrue(result["success"])
        self.assertEqual(result["deleted"], 0)
        self.assertEqual(result["skipped"], 1)
        self.assertTrue(any("Skip shared file" in line for line in result["details"]))
        remove_mock.assert_not_called()
        delete_file_mock.assert_not_called()

    @patch("app.library.delete_file_by_filepath")
    @patch("app.library.os.remove")
    @patch("app.library.os.path.exists", return_value=False)
    def test_delete_target_apps_cleans_db_when_disk_file_missing(
        self,
        exists_mock,
        remove_mock,
        delete_file_mock,
    ):
        target_app = self._make_app(1, "0100AAAA", "UPDATE", 3)
        file_entry = self._make_file(102, "X:\\library\\missing.nsp", [target_app])
        target_app.files = [file_entry]

        result = _delete_target_apps([target_app], dry_run=False, verbose=True)

        self.assertTrue(result["success"])
        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["skipped"], 0)
        remove_mock.assert_not_called()
        delete_file_mock.assert_called_once_with("X:\\library\\missing.nsp")

    def test_delete_library_content_rejects_unknown_scope(self):
        result = delete_library_content("unknown-scope", dry_run=True)

        self.assertFalse(result["success"])
        self.assertTrue(any("Unsupported delete scope" in err for err in result["errors"]))

    def test_manage_delete_updates_api_does_not_report_skipped_items(self):
        fake_user = self._AdminUser()

        with flask_app.test_request_context("/api/manage/delete-updates", method="POST", json={"dry_run": True, "verbose": True}):
            with (
                patch("app.auth.admin_account_created", return_value=True),
                patch("app.auth.current_user", fake_user),
                patch("app.app.delete_older_updates", return_value={"success": True, "deleted": 3, "skipped": 0, "details": ["Deleted: X:\\library\\old-update.nsp."], "errors": []}),
            ):
                from app.app import manage_delete_updates
                response = manage_delete_updates()

        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["deleted"], 3)
        self.assertEqual(payload["skipped"], 0)
        self.assertEqual(payload["details"], ["Deleted: X:\\library\\old-update.nsp."])

    @patch("app.app.post_library_change")
    @patch("app.app.delete_older_updates")
    def test_manage_delete_updates_runs_post_change_when_mutated_despite_errors(
        self,
        delete_updates_mock,
        post_library_change_mock,
    ):
        delete_updates_mock.return_value = {
            "success": False,
            "deleted": 1,
            "skipped": 0,
            "mutated": True,
            "details": ["Deleted: X:\\library\\old-update.nsp."],
            "errors": ["one file failed"],
        }

        with flask_app.test_request_context("/api/manage/delete-updates", method="POST", json={}):
            from app.app import manage_delete_updates
            response = manage_delete_updates.__wrapped__()

        payload = response.get_json()
        self.assertFalse(payload["success"])
        post_library_change_mock.assert_called_once_with()

    def test_manage_delete_duplicates_api_does_not_report_skipped_items(self):
        fake_user = self._AdminUser()

        with flask_app.test_request_context("/api/manage/delete-duplicates", method="POST", json={"dry_run": True, "verbose": True}):
            with (
                patch("app.auth.admin_account_created", return_value=True),
                patch("app.auth.current_user", fake_user),
                patch("app.app.delete_duplicates", return_value={"success": True, "deleted": 1, "skipped": 0, "details": ["Keep 0100DUPES0000000 v1: X:\\library\\keeper.nsz (ext=nsz, size=100).", "Plan delete duplicate 0100DUPES0000000 v1: X:\\library\\duplicate.nsp (ext=nsp, size=90)."], "errors": []}),
            ):
                from app.app import manage_delete_duplicates
                response = manage_delete_duplicates()

        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["deleted"], 1)
        self.assertEqual(payload["skipped"], 0)
        self.assertFalse(any(line.startswith("Skip ") for line in payload["details"]))

    @patch("app.app.post_library_change")
    @patch("app.app.delete_duplicates")
    def test_manage_delete_duplicates_runs_post_change_when_mutated_despite_errors(
        self,
        delete_duplicates_mock,
        post_library_change_mock,
    ):
        delete_duplicates_mock.return_value = {
            "success": False,
            "deleted": 1,
            "skipped": 0,
            "mutated": True,
            "details": ["Deleted duplicate 0100DUPES0000000 v1: X:\\library\\duplicate.nsp."],
            "errors": ["cleanup failed"],
        }

        with flask_app.test_request_context("/api/manage/delete-duplicates", method="POST", json={}):
            from app.app import manage_delete_duplicates
            response = manage_delete_duplicates.__wrapped__()

        payload = response.get_json()
        self.assertFalse(payload["success"])
        post_library_change_mock.assert_called_once_with()

    @patch("app.library.os.path.getmtime")
    @patch("app.library.os.path.exists", return_value=True)
    @patch("app.library.Apps")
    def test_delete_duplicates_prefers_newer_detected_version_over_extension_priority(
        self,
        apps_mock,
        exists_mock,
        getmtime_mock,
    ):
        app = self._make_app(1, "0100AAAA00000800", "UPDATE", 131072)
        older_file = self._make_file(101, "X:\\library\\Example Title [0100AAAA00000800] [v65536].nsz", [app])
        older_file.extension = "nsz"
        older_file.size = 500
        newer_file = self._make_file(102, "X:\\library\\Example Title [0100AAAA00000800] [v131072].nsp", [app])
        newer_file.extension = "nsp"
        newer_file.size = 400
        app.files = [older_file, newer_file]

        apps_mock.owned.is_.return_value = True
        apps_mock.query.filter.return_value.all.return_value = [app]
        getmtime_mock.side_effect = lambda path: {
            older_file.filepath: 200,
            newer_file.filepath: 100,
        }[path]

        result = delete_duplicates(dry_run=True, verbose=True)

        self.assertTrue(result["success"])
        self.assertEqual(result["deleted"], 1)
        self.assertIn(newer_file.filepath, result["details"][0])
        self.assertIn(older_file.filepath, result["details"][1])

    @patch("app.library.os.path.getmtime")
    @patch("app.library.os.path.exists", return_value=True)
    @patch("app.library.Apps")
    def test_delete_duplicates_falls_back_to_extension_priority_without_version_tokens(
        self,
        apps_mock,
        exists_mock,
        getmtime_mock,
    ):
        app = self._make_app(1, "0100BBBB00000800", "UPDATE", 0)
        preferred_file = self._make_file(201, "X:\\library\\Example Preferred [0100BBBB00000800].nsz", [app])
        preferred_file.extension = "nsz"
        preferred_file.size = 300
        other_file = self._make_file(202, "X:\\library\\Example Other [0100BBBB00000800].nsp", [app])
        other_file.extension = "nsp"
        other_file.size = 400
        app.files = [preferred_file, other_file]

        apps_mock.owned.is_.return_value = True
        apps_mock.query.filter.return_value.all.return_value = [app]
        getmtime_mock.side_effect = lambda path: {
            preferred_file.filepath: 100,
            other_file.filepath: 200,
        }[path]

        result = delete_duplicates(dry_run=True, verbose=True)

        self.assertTrue(result["success"])
        self.assertEqual(result["deleted"], 1)
        self.assertIn(preferred_file.filepath, result["details"][0])
        self.assertIn(other_file.filepath, result["details"][1])

    def test_manage_delete_orphaned_addons_api_does_not_report_skipped_items(self):
        fake_user = self._AdminUser()

        with flask_app.test_request_context("/api/manage/delete-orphaned-addons", method="POST", json={"dry_run": True, "verbose": True}):
            with (
                patch("app.auth.admin_account_created", return_value=True),
                patch("app.auth.current_user", fake_user),
                patch("app.app.delete_orphaned_addons", return_value={"success": True, "deleted": 2, "skipped": 0, "details": ["Deleted: X:\\library\\orphaned-dlc.nsp."], "errors": [], "mutated": False}),
            ):
                from app.app import manage_delete_orphaned_addons
                response = manage_delete_orphaned_addons()

        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["deleted"], 2)
        self.assertEqual(payload["skipped"], 0)
        self.assertEqual(payload["details"], ["Deleted: X:\\library\\orphaned-dlc.nsp."])

    @patch("app.library.delete_file_by_filepath")
    @patch("app.library.os.remove")
    @patch("app.library.os.path.exists", return_value=True)
    def test_delete_target_apps_marks_mutated_on_success(
        self,
        exists_mock,
        remove_mock,
        delete_file_mock,
    ):
        target_app = self._make_app(1, "0100CCCC", "UPDATE", 5)
        file_entry = self._make_file(103, "X:\\library\\owned.nsp", [target_app])
        target_app.files = [file_entry]

        result = _delete_target_apps([target_app], dry_run=False, verbose=False)

        self.assertTrue(result["mutated"])

    @patch("app.library.delete_file_by_filepath")
    @patch("app.library.os.remove")
    @patch("app.library.os.path.exists", return_value=True)
    def test_delete_target_apps_dry_run_does_not_mark_mutated(
        self,
        exists_mock,
        remove_mock,
        delete_file_mock,
    ):
        target_app = self._make_app(1, "0100DDDD", "UPDATE", 7)
        file_entry = self._make_file(104, "X:\\library\\dryrun.nsp", [target_app])
        target_app.files = [file_entry]

        result = _delete_target_apps([target_app], dry_run=True, verbose=False)

        self.assertFalse(result["mutated"])
        remove_mock.assert_not_called()
        delete_file_mock.assert_not_called()

    def test_app_has_deletable_files_rejects_shared_only_files(self):
        target_app = self._make_app(1, "0100EEEE", "UPDATE", 1)
        foreign_app = self._make_app(2, "0100FFFF", "BASE", 0)
        target_app.files = [self._make_file(105, "X:\\library\\shared.xci", [target_app, foreign_app])]

        self.assertFalse(_app_has_deletable_files(target_app))

    def test_build_deletable_version_map_marks_only_exclusive_owned_versions(self):
        exclusive_app = self._make_app(1, "0100AAAA", "UPDATE", 3)
        exclusive_app.owned = True
        exclusive_app.files = [self._make_file(201, "X:\\library\\owned.nsp", [exclusive_app])]
        shared_app = self._make_app(2, "0100BBBB", "DLC", 1)
        shared_app.owned = True
        foreign_app = self._make_app(3, "0100CCCC", "BASE", 0)
        shared_app.files = [self._make_file(202, "X:\\library\\shared.xci", [shared_app, foreign_app])]

        deletable = _build_deletable_version_map([exclusive_app, shared_app])

        self.assertTrue(deletable[("0100AAAA", "UPDATE", "3")])
        self.assertFalse(deletable[("0100BBBB", "DLC", "1")])

    @patch("app.app.titles.get_game_info")
    @patch("app.app.titles.get_all_app_existing_versions")
    @patch("app.app.titles.get_all_existing_dlc")
    @patch("app.app.db.session.query")
    def test_build_title_details_dlc_items_falls_back_to_title_level_dlc_lookup(
        self,
        query_mock,
        get_all_existing_dlc_mock,
        get_all_app_existing_versions_mock,
        get_game_info_mock,
    ):
        query_mock.return_value.filter.return_value.all.return_value = []
        get_all_existing_dlc_mock.return_value = ["0100AAAA00001001", "0100AAAA00001002"]
        get_all_app_existing_versions_mock.side_effect = lambda app_id: [0, 5] if app_id == "0100AAAA00001001" else [0]
        get_game_info_mock.side_effect = lambda app_id: {"name": f"Addon {app_id[-4:]}"} if app_id else {}

        dlc_items, has_all_dlcs = _build_title_details_dlc_items(123, "0100AAAA00000000")

        self.assertEqual(
            dlc_items,
            [
                {
                    "app_id": "0100AAAA00001001",
                    "name": "Addon 1001",
                    "latest_version": 5,
                    "owned_version": None,
                    "owned": False,
                    "ignored": False,
                },
                {
                    "app_id": "0100AAAA00001002",
                    "name": "Addon 1002",
                    "latest_version": 0,
                    "owned_version": None,
                    "owned": False,
                    "ignored": False,
                },
            ],
        )
        self.assertFalse(has_all_dlcs)

    @patch("app.app.titles.get_game_info", return_value={"name": "Optional language pack"})
    @patch("app.app.titles.get_all_app_existing_versions", return_value=[0])
    @patch("app.app.db.session.query")
    def test_build_title_details_dlc_items_treats_ignored_dlc_as_complete(
        self,
        query_mock,
        get_all_app_existing_versions_mock,
        get_game_info_mock,
    ):
        query_mock.return_value.filter.return_value.all.return_value = [
            SimpleNamespace(app_id="0100AAAA00001001", app_version="0", owned=False, ignored=True),
        ]

        dlc_items, has_all_dlcs = _build_title_details_dlc_items(123, "0100AAAA00000000")

        self.assertTrue(has_all_dlcs)
        self.assertEqual(dlc_items[0]["name"], "Optional language pack")
        self.assertTrue(dlc_items[0]["ignored"])
        self.assertFalse(dlc_items[0]["owned"])

    @patch("app.app._run_post_library_change")
    @patch("app.app.post_library_change")
    @patch("app.app.delete_library_content")
    def test_manage_delete_library_content_uses_sync_post_change(
        self,
        delete_content_mock,
        post_library_change_mock,
        run_post_library_change_mock,
    ):
        delete_content_mock.return_value = {
            "success": True,
            "deleted": 1,
            "skipped": 0,
            "mutated": True,
            "errors": [],
            "details": [],
        }

        with flask_app.test_request_context(
            "/api/manage/delete-library-content",
            method="POST",
            json={"scope": "title_cascade", "title_id": "0100AAAA00000000"},
        ):
            response, status_code = manage_delete_library_content.__wrapped__()

        self.assertEqual(status_code, 200)
        self.assertTrue(response.get_json()["success"])
        run_post_library_change_mock.assert_called_once_with()
        post_library_change_mock.assert_not_called()

    @patch("app.app._run_post_library_change")
    @patch("app.app.delete_library_content")
    def test_manage_delete_library_content_skips_sync_post_change_for_dry_run(
        self,
        delete_content_mock,
        run_post_library_change_mock,
    ):
        delete_content_mock.return_value = {
            "success": True,
            "deleted": 1,
            "skipped": 0,
            "mutated": True,
            "errors": [],
            "details": [],
        }

        with flask_app.test_request_context(
            "/api/manage/delete-library-content",
            method="POST",
            json={"scope": "title_cascade", "title_id": "0100AAAA00000000", "dry_run": True},
        ):
            response, status_code = manage_delete_library_content.__wrapped__()

        self.assertEqual(status_code, 200)
        self.assertTrue(response.get_json()["success"])
        run_post_library_change_mock.assert_not_called()

    @patch("app.app._run_post_library_change")
    @patch("app.app.delete_library_content")
    def test_manage_delete_library_content_skips_sync_post_change_when_not_mutated(
        self,
        delete_content_mock,
        run_post_library_change_mock,
    ):
        delete_content_mock.return_value = {
            "success": False,
            "deleted": 0,
            "skipped": 1,
            "mutated": False,
            "errors": ["Delete failed."],
            "details": [],
        }

        with flask_app.test_request_context(
            "/api/manage/delete-library-content",
            method="POST",
            json={"scope": "title_cascade", "title_id": "0100AAAA00000000"},
        ):
            response, status_code = manage_delete_library_content.__wrapped__()

        self.assertEqual(status_code, 400)
        self.assertFalse(response.get_json()["success"])
        run_post_library_change_mock.assert_not_called()

    @patch("app.app.post_library_change")
    @patch("app.app.organize_library")
    def test_manage_organize_library_runs_post_change_when_mutated_despite_errors(
        self,
        organize_library_mock,
        post_library_change_mock,
    ):
        organize_library_mock.return_value = {
            "success": False,
            "moved": 2,
            "skipped": 0,
            "folders_deleted": 0,
            "folders_failed": 0,
            "mutated": True,
            "errors": ["one file failed"],
            "details": [],
        }

        with flask_app.test_request_context("/api/manage/organize", method="POST", json={}):
            from app.app import manage_organize_library
            response = manage_organize_library.__wrapped__()

        self.assertFalse(response.get_json()["success"])
        post_library_change_mock.assert_called_once_with()

    @patch("app.app.post_library_change")
    @patch("app.app.convert_to_nsz")
    def test_manage_convert_nsz_runs_post_change_when_mutated_despite_errors(
        self,
        convert_mock,
        post_library_change_mock,
    ):
        convert_mock.return_value = {
            "success": False,
            "converted": 1,
            "skipped": 0,
            "mutated": True,
            "errors": ["one file failed"],
            "details": [],
        }

        with flask_app.test_request_context("/api/manage/convert", method="POST", json={"command": "nsz"}):
            from app.app import manage_convert_nsz
            response = manage_convert_nsz.__wrapped__()

        self.assertFalse(response.get_json()["success"])
        post_library_change_mock.assert_called_once_with()

    @patch("app.app.post_library_change")
    @patch("app.app.convert_single_to_nsz")
    def test_manage_convert_single_runs_post_change_when_mutated_despite_errors(
        self,
        convert_single_mock,
        post_library_change_mock,
    ):
        convert_single_mock.return_value = {
            "success": False,
            "converted": 1,
            "skipped": 0,
            "mutated": True,
            "errors": ["verify failed after write"],
            "details": [],
        }

        with flask_app.test_request_context("/api/manage/convert-single", method="POST", json={"file_id": 1, "command": "nsz"}):
            from app.app import manage_convert_single
            response = manage_convert_single.__wrapped__()

        self.assertFalse(response.get_json()["success"])
        post_library_change_mock.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
