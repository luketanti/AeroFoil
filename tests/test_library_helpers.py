import unittest
from unittest.mock import patch

from app.library import (
    _cleanup_import_staging_roots,
    _format_nsz_command,
    _pending_cleanup_roots,
    _pending_organize_paths,
    _sanitize_component,
    enqueue_cleanup_roots,
    enqueue_organize_paths,
)


class LibraryHelperTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
