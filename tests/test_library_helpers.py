import unittest
from collections import namedtuple
from types import SimpleNamespace
from unittest.mock import patch

from app.app import _sort_library_rows_by_title_name
from app.library import (
    _cleanup_import_staging_roots,
    _delete_target_apps,
    _format_nsz_command,
    _pending_cleanup_roots,
    _pending_organize_paths,
    _sanitize_component,
    delete_older_updates,
    enqueue_cleanup_roots,
    enqueue_organize_paths,
    delete_library_content,
    delete_orphaned_addons,
)
from app.app import app as flask_app


class LibraryHelperTests(unittest.TestCase):
    class _InvertibleExpr:
        def __invert__(self):
            return self

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

    def test_sanitize_component(self):
        self.assertEqual(_sanitize_component('Game: Name?'), 'Game Name')
        self.assertEqual(_sanitize_component(''), 'Unknown')

    def test_format_nsz_command_threads(self):
        command = _format_nsz_command(
            '{nsz_exe} -C -o "{output_dir}" "{input_file}"',
            'C:\\input.nsp',
            'C:\\output.nsz',
            threads=4
        )
        self.assertIn('-t 4', command)
        self.assertIn('input.nsp', command)

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
            self.assertEqual(_pending_organize_paths, {
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
            ("X:\\fixture-root\\Example Release NSW-GRP\\subdir", [], ["keep.nsp", "proof.nfo"]),
            ("X:\\fixture-root\\Example Release NSW-GRP", ["subdir"], ["notes.txt"]),
        ]

        _cleanup_import_staging_roots(["X:\\fixture-root\\Example Release NSW-GRP"])

        self.assertEqual(
            [call.args[0] for call in remove_mock.call_args_list],
            [
                "X:\\fixture-root\\Example Release NSW-GRP\\subdir\\proof.nfo",
                "X:\\fixture-root\\Example Release NSW-GRP\\notes.txt",
            ],
        )

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

    @patch("app.library._delete_target_apps", return_value={"success": True, "deleted": 2, "skipped": 0, "mutated": False, "errors": [], "details": []})
    def test_delete_orphaned_addons_uses_targeted_delete_helper(self, delete_targets_mock):
        with flask_app.app_context():
            with patch("app.library.Apps.query") as apps_query_mock, patch("app.library.db.session.query") as session_query_mock:
                session_query_mock.return_value.filter.return_value.exists.return_value = self._InvertibleExpr()
                apps_query_mock.join.return_value.filter.return_value.all.return_value = ["orphan-app"]

                result = delete_orphaned_addons(dry_run=True, verbose=True)

        self.assertTrue(result["success"])
        delete_targets_mock.assert_called_once_with(
            ["orphan-app"],
            dry_run=True,
            verbose=True,
            detail_limit=200,
        )

    @patch("app.library._delete_target_apps")
    def test_delete_older_updates_skips_shared_base_xci(self, delete_targets_mock):
        title = SimpleNamespace(id=1, title_id="01005270232F2000")
        older_update = self._make_app(10, "01005270232F2800", "UPDATE", 1)
        latest_update = self._make_app(11, "01005270232F2800", "UPDATE", 2)
        base_app = self._make_app(12, "01005270232F2000", "BASE", 0)
        shared_file = self._make_file(
            201,
            "X:\\library\\Example Title [01005270232F2000] [BASE][v0].xci",
            [older_update, base_app],
        )
        older_update.files = [shared_file]
        delete_targets_mock.return_value = {
            "success": True,
            "deleted": 0,
            "skipped": 1,
            "mutated": False,
            "errors": [],
            "details": [
                "Skip shared file X:\\library\\Example Title [01005270232F2000] [BASE][v0].xci: linked to non-target apps BASE 01005270232F2000 v0."
            ],
        }

        with flask_app.app_context():
            with patch("app.library.Titles.query") as titles_query_mock, patch("app.library.Apps.query") as apps_query_mock:
                titles_query_mock.all.return_value = [title]
                apps_query_mock.filter_by.return_value.all.return_value = [older_update, latest_update]

                result = delete_older_updates(dry_run=True, verbose=True)

        self.assertTrue(result["success"])
        self.assertEqual(result["deleted"], 0)
        self.assertEqual(result["skipped"], 1)
        self.assertTrue(any("Skip shared file" in line for line in result["details"]))
        delete_targets_mock.assert_called_once_with(
            [older_update],
            dry_run=True,
            verbose=True,
            detail_limit=200,
        )

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


if __name__ == '__main__':
    unittest.main()
