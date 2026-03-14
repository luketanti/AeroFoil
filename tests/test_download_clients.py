import unittest
from unittest.mock import patch

from app.downloads.client import queue_download
from app.downloads.manager import (
    _check_completed,
    _adopt_untracked_completed_item,
    _format_pending_label,
    _infer_update_info_from_completed_item,
    _iter_importable_download_files,
    _normalize_imported_wrapped_files,
    get_downloads_state,
    queue_download_url,
)
from app.downloads.prowlarr import _normalize_result
from app.downloads.usenet_client import add_nzb, list_active
from app.downloads.usenet_client import _restrict_job_to_matching_update_files


class ProwlarrProtocolTests(unittest.TestCase):
    def test_normalize_result_detects_torrent_protocol_from_magnet(self):
        result = _normalize_result({
            "title": "Example Torrent",
            "downloadUrl": "magnet:?xt=urn:btih:abcdef",
        })
        self.assertEqual(result["protocol"], "torrent")

    def test_normalize_result_detects_usenet_protocol_from_nzb_url(self):
        result = _normalize_result({
            "title": "Example NZB",
            "downloadUrl": "https://indexer.example/file.nzb",
        })
        self.assertEqual(result["protocol"], "usenet")


class QueueRoutingTests(unittest.TestCase):
    @patch("app.downloads.manager.queue_download")
    @patch("app.downloads.manager.load_settings")
    def test_queue_download_url_routes_to_torrent_client(self, load_settings_mock, queue_download_mock):
        load_settings_mock.return_value = {
            "downloads": {
                "torrent_client": {
                    "type": "qbittorrent",
                    "url": "http://torrent.local",
                    "username": "user",
                    "password": "pass",
                    "category": "aerofoil",
                    "download_path": "D:\\Downloads",
                },
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                },
            }
        }
        queue_download_mock.return_value = (True, "ok", "abc123")

        ok, message = queue_download_url("magnet:?xt=urn:btih:abcdef", expected_name="Game")

        self.assertTrue(ok)
        self.assertEqual(message, "Queued download.")
        queue_download_mock.assert_called_once()
        self.assertEqual(queue_download_mock.call_args.args[0], "torrent")
        self.assertEqual(queue_download_mock.call_args.args[1]["url"], "http://torrent.local")

    @patch("app.downloads.manager.queue_download")
    @patch("app.downloads.manager.load_settings")
    def test_queue_download_url_routes_to_usenet_client(self, load_settings_mock, queue_download_mock):
        load_settings_mock.return_value = {
            "downloads": {
                "torrent_client": {
                    "type": "qbittorrent",
                    "url": "http://torrent.local",
                    "username": "user",
                    "password": "pass",
                    "category": "aerofoil",
                    "download_path": "D:\\Downloads",
                },
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                },
            }
        }
        queue_download_mock.return_value = (True, "ok", "nzo123")

        ok, message = queue_download_url("https://indexer.example/file.nzb", expected_name="Game", protocol="usenet")

        self.assertTrue(ok)
        self.assertEqual(message, "Queued download.")
        queue_download_mock.assert_called_once()
        self.assertEqual(queue_download_mock.call_args.args[0], "usenet")
        self.assertEqual(queue_download_mock.call_args.args[1]["url"], "http://sab.local")

    @patch("app.downloads.manager.queue_download")
    @patch("app.downloads.manager.load_settings")
    def test_manual_usenet_update_queue_does_not_use_update_only(self, load_settings_mock, queue_download_mock):
        load_settings_mock.return_value = {
            "downloads": {
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                },
            }
        }
        queue_download_mock.return_value = (True, "ok", "nzo123")

        ok, message = queue_download_url(
            "https://indexer.example/file.nzb",
            expected_name="Game Update",
            protocol="usenet",
            update_only=True,
            expected_version=123,
            title_id="0100000000010000",
        )

        self.assertTrue(ok)
        self.assertEqual(message, "Queued download.")
        queue_download_mock.assert_called_once()
        self.assertEqual(queue_download_mock.call_args.args[0], "usenet")
        self.assertFalse(queue_download_mock.call_args.kwargs["update_only"])
        self.assertEqual(queue_download_mock.call_args.kwargs["expected_version"], 123)

    def test_format_pending_label_falls_back_to_expected_name_for_manual_items(self):
        self.assertEqual(
            _format_pending_label({
                "title_id": None,
                "version": None,
                "expected_name": "Example Release NSW-GRP",
            }),
            "Example Release NSW-GRP",
        )

    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 123.0,
        "pending": {
            "manual:1": {
                "title_id": None,
                "version": None,
                "hash": "SABnzbd_nzo_2goo76g2",
                "id": "SABnzbd_nzo_2goo76g2",
                "expected_name": "Example Release NSW-GRP",
                "title_name": "Example Release NSW-GRP",
                "protocol": "usenet",
                "client_type": "sabnzbd",
            }
        },
        "completed": set(),
    })
    def test_get_downloads_state_exposes_label_for_manual_pending_items(self, _state_lock_mock):
        state = get_downloads_state()

        self.assertEqual(state["pending"][0]["label"], "Example Release NSW-GRP")
        self.assertEqual(state["pending"][0]["expected_name"], "Example Release NSW-GRP")
        self.assertIsNone(state["pending"][0]["title_id"])
        self.assertIsNone(state["pending"][0]["version"])

    @patch("app.downloads.client.add_nzb")
    def test_queue_download_forwards_update_selection_to_usenet_client(self, add_nzb_mock):
        add_nzb_mock.return_value = (True, "ok", "nzo123")

        ok, message, item_id = queue_download(
            "usenet",
            {
                "type": "sabnzbd",
                "url": "http://sab.local",
                "api_key": "secret",
                "category": "aerofoil",
            },
            "https://indexer.example/file.nzb",
            expected_name="Game Update",
            update_only=True,
            exclude_russian=True,
            expected_version=123,
        )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        self.assertEqual(item_id, "nzo123")
        add_nzb_mock.assert_called_once()
        self.assertTrue(add_nzb_mock.call_args.kwargs["update_only"])
        self.assertTrue(add_nzb_mock.call_args.kwargs["exclude_russian"])
        self.assertEqual(add_nzb_mock.call_args.kwargs["expected_version"], 123)


class SabSelectionTests(unittest.TestCase):
    @patch("app.downloads.usenet_client.time.sleep")
    @patch("app.downloads.usenet_client._get_job_files")
    def test_restrict_job_retries_until_file_list_available(self, get_job_files_mock, sleep_mock):
        get_job_files_mock.side_effect = [
            [],
            [
                {"filename": "Game [v1].nsp", "nzf_id": "1"},
                {"filename": "Game [v2].nsp", "nzf_id": "2"},
            ],
        ]

        with patch("app.downloads.usenet_client._delete_job_files", return_value=True) as delete_job_files_mock:
            ok, message = _restrict_job_to_matching_update_files(
                "http://sab.local",
                "secret",
                "nzo123",
                expected_version=2,
            )

        self.assertTrue(ok)
        self.assertIsNone(message)
        sleep_mock.assert_called_once_with(1)
        delete_job_files_mock.assert_called_once()
        self.assertEqual(delete_job_files_mock.call_args.args[3], ["1"])

    @patch("app.downloads.usenet_client._delete_job")
    @patch("app.downloads.usenet_client._resume_job", return_value=False)
    @patch("app.downloads.usenet_client._restrict_job_to_matching_update_files", return_value=(True, None))
    @patch("app.downloads.usenet_client._sab_request")
    def test_add_nzb_fails_when_resume_fails(
        self,
        sab_request_mock,
        restrict_mock,
        resume_mock,
        delete_job_mock,
    ):
        sab_request_mock.return_value = {"status": True, "nzo_ids": ["nzo123"]}

        ok, message, item_id = add_nzb(
            "http://sab.local",
            "secret",
            "https://indexer.example/file.nzb",
            update_only=True,
            expected_version=2,
        )

        self.assertFalse(ok)
        self.assertIn("failed to resume", message.lower())
        self.assertIsNone(item_id)
        restrict_mock.assert_called_once()
        resume_mock.assert_called_once()
        delete_job_mock.assert_called_once_with("http://sab.local", "secret", "nzo123", timeout_seconds=15)

    @patch("app.downloads.usenet_client._sab_request")
    def test_list_active_uses_queue_speed(self, sab_request_mock):
        sab_request_mock.return_value = {
            "queue": {
                "kbpersec": "512.5",
                "slots": [
                    {
                        "nzo_id": "nzo123",
                        "filename": "Game Update",
                        "status": "Downloading",
                        "percentage": "50",
                        "mb": "100",
                        "mbleft": "50",
                        "timeleft": "00:10:00",
                        "cat": "aerofoil",
                    }
                ],
            }
        }

        items = list_active("http://sab.local", "secret", category="aerofoil")

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["down_speed"], int(512.5 * 1024))


class CompletedAdoptionTests(unittest.TestCase):
    @patch("app.downloads.manager.os.walk")
    @patch("app.downloads.manager.os.path.isdir", return_value=True)
    @patch("app.downloads.manager.os.path.isfile")
    def test_iter_importable_download_files_ignores_scene_extras(
        self,
        isfile_mock,
        isdir_mock,
        walk_mock,
    ):
        walk_mock.return_value = [
            ("X:\\fixture-root\\Example Release NSW-GRP", [], [
                "example-base.nsp.hdf",
                "example-update.nsp",
                "proof.nfo",
                "checksum.sfv",
            ]),
        ]
        isfile_mock.side_effect = lambda path: str(path).lower().endswith((
            "example-base.nsp.hdf",
            "example-update.nsp",
            "proof.nfo",
            "checksum.sfv",
        ))

        self.assertEqual(
            _iter_importable_download_files("X:\\fixture-root\\Example Release NSW-GRP"),
            [
                "X:\\fixture-root\\Example Release NSW-GRP\\example-base.nsp.hdf",
                "X:\\fixture-root\\Example Release NSW-GRP\\example-update.nsp",
            ],
        )

    @patch("app.downloads.manager.shutil.move")
    @patch("app.downloads.manager._ensure_unique_path", side_effect=lambda path: path)
    @patch("app.downloads.manager.os.walk")
    @patch("app.downloads.manager.os.path.isdir", return_value=True)
    @patch("app.downloads.manager.os.path.isfile", return_value=False)
    @patch("app.downloads.manager.os.path.exists", return_value=True)
    def test_normalize_imported_wrapped_files_strips_hdf_inside_directories(
        self,
        exists_mock,
        isfile_mock,
        isdir_mock,
        walk_mock,
        ensure_unique_path_mock,
        move_mock,
    ):
        walk_mock.return_value = [
            ("X:\\fixture-root\\Example Release NSW-GRP", [], ["base.nsp.hdf", "note.nfo", "update.nsz.hdf"]),
        ]

        result = _normalize_imported_wrapped_files("X:\\fixture-root\\Example Release NSW-GRP")

        self.assertEqual(result, "X:\\fixture-root\\Example Release NSW-GRP")
        self.assertEqual(move_mock.call_args_list[0].args, (
            "X:\\fixture-root\\Example Release NSW-GRP\\base.nsp.hdf",
            "X:\\fixture-root\\Example Release NSW-GRP\\base.nsp",
        ))
        self.assertEqual(move_mock.call_args_list[1].args, (
            "X:\\fixture-root\\Example Release NSW-GRP\\update.nsz.hdf",
            "X:\\fixture-root\\Example Release NSW-GRP\\update.nsz",
        ))

    @patch("app.downloads.manager.shutil.move")
    @patch("app.downloads.manager._ensure_unique_path", side_effect=lambda path: path)
    @patch("app.downloads.manager.os.path.isdir", return_value=False)
    @patch("app.downloads.manager.os.path.isfile", return_value=True)
    @patch("app.downloads.manager.os.path.exists", return_value=True)
    def test_normalize_imported_wrapped_files_returns_new_single_file_path(
        self,
        exists_mock,
        isfile_mock,
        isdir_mock,
        ensure_unique_path_mock,
        move_mock,
    ):
        result = _normalize_imported_wrapped_files("X:\\fixture-root\\incoming\\example-base.nsp.hdf")

        self.assertEqual(result, "X:\\fixture-root\\incoming\\example-base.nsp")
        move_mock.assert_called_once_with(
            "X:\\fixture-root\\incoming\\example-base.nsp.hdf",
            "X:\\fixture-root\\incoming\\example-base.nsp",
        )

    @patch("app.downloads.manager.enqueue_organize_paths")
    @patch("app.downloads.manager.enqueue_cleanup_roots")
    @patch("app.downloads.manager.remove_completed_download", return_value=(True, "ok"))
    @patch("app.downloads.manager._move_completed", return_value="X:\\fixture-root\\Example Title [0100]\\Example Base.nsp")
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "manual:1": {
                "title_id": None,
                "version": None,
                "hash": "item-123",
                "id": "item-123",
                "expected_name": "Example Release NSW-GRP",
                "title_name": "Example Release NSW-GRP",
                "protocol": "usenet",
                "client_type": "sabnzbd",
            }
        },
        "completed": set(),
    })
    def test_check_completed_enqueues_paths_before_post_processing(
        self,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
        move_completed_mock,
        remove_completed_mock,
        enqueue_cleanup_roots_mock,
        enqueue_paths_mock,
    ):
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd"})]
        list_completed_mock.return_value = [{
            "id": "item-123",
            "hash": "item-123",
            "name": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        }]
        events = []

        def scan_cb():
            events.append("scan")

        def post_cb():
            events.append("post")

        enqueue_paths_mock.side_effect = lambda paths: events.append(("enqueue", list(paths)))
        enqueue_cleanup_roots_mock.side_effect = lambda paths: events.append(("cleanup", list(paths)))

        _check_completed({}, scan_cb=scan_cb, post_cb=post_cb)

        self.assertEqual(events, [
            ("enqueue", ["X:\\fixture-root\\Example Title [0100]\\Example Base.nsp"]),
            ("cleanup", []),
            "scan",
            "post",
        ])

    @patch("app.downloads.manager.os.path.isdir", return_value=True)
    @patch("app.downloads.manager.enqueue_organize_paths")
    @patch("app.downloads.manager.enqueue_cleanup_roots")
    @patch("app.downloads.manager.remove_completed_download", return_value=(True, "ok"))
    @patch("app.downloads.manager._move_completed", return_value="X:\\fixture-root\\Example Release NSW-GRP")
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {},
        "completed": set(),
    })
    def test_check_completed_enqueues_cleanup_roots_for_release_directories(
        self,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
        move_completed_mock,
        remove_completed_mock,
        enqueue_cleanup_roots_mock,
        enqueue_paths_mock,
        isdir_mock,
    ):
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd"})]
        list_completed_mock.return_value = [{
            "id": "item-123",
            "hash": "item-123",
            "name": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        }]

        _check_completed({})

        enqueue_paths_mock.assert_called_once_with(["X:\\fixture-root\\Example Release NSW-GRP"])
        enqueue_cleanup_roots_mock.assert_called_once_with(["X:\\fixture-root\\Example Release NSW-GRP"])

    @patch("app.downloads.manager.titles_lib.release_titledb")
    @patch("app.downloads.manager.titles_lib.get_game_info", return_value={"name": "Sample Game"})
    @patch("app.downloads.manager.titles_lib.get_all_existing_versions", return_value=[{"version": 1245184}])
    @patch("app.downloads.manager.titles_lib.load_titledb")
    @patch("app.downloads.manager.get_all_titles")
    @patch("app.downloads.manager._iter_completed_files")
    def test_infer_update_info_uses_completed_file_names_for_matching(
        self,
        iter_files_mock,
        get_all_titles_mock,
        load_titledb_mock,
        get_versions_mock,
        get_game_info_mock,
        release_titledb_mock,
    ):
        class _Title:
            title_id = "0100B6E012EBE000"

        get_all_titles_mock.return_value = [_Title()]
        iter_files_mock.side_effect = lambda _path: iter([
            "C:\\tests\\completed\\Random Folder\\sample-game_v1245184.nsp.hdf",
        ])

        inferred = _infer_update_info_from_completed_item({
            "name": "Random Folder",
            "path": "C:\\tests\\completed\\Random Folder",
        })

        self.assertEqual(inferred, {
            "title_id": "0100B6E012EBE000",
            "title_name": "Sample Game",
            "version": 1245184,
        })
        load_titledb_mock.assert_called_once()
        get_versions_mock.assert_called_once_with("0100B6E012EBE000")
        get_game_info_mock.assert_called_once_with("0100B6E012EBE000")
        release_titledb_mock.assert_called_once()

    @patch("app.downloads.manager._move_completed", return_value="C:\\tests\\library\\Sample Game [0100]\\Updates\\v1245184\\Sample Game.nsp")
    @patch("app.downloads.manager._infer_update_info_from_completed_item")
    def test_adopt_untracked_completed_item_uses_inferred_update_info(self, infer_mock, move_mock):
        infer_mock.return_value = {
            "title_id": "0100B6E012EBE000",
            "title_name": "Sample Game",
            "version": 1245184,
        }

        moved = _adopt_untracked_completed_item({
            "name": "Sample Update v1.1.10 TEST-GRP",
            "path": "C:\\tests\\completed\\Sample Update v1.1.10 TEST-GRP",
        })

        self.assertEqual(moved, "C:\\tests\\library\\Sample Game [0100]\\Updates\\v1245184\\Sample Game.nsp")
        move_mock.assert_called_once_with(
            {
                "name": "Sample Update v1.1.10 TEST-GRP",
                "path": "C:\\tests\\completed\\Sample Update v1.1.10 TEST-GRP",
            },
            infer_mock.return_value,
        )

    @patch("app.downloads.manager._move_completed", return_value="C:\\tests\\library\\Random NZB Upload")
    @patch("app.downloads.manager._infer_update_info_from_completed_item", return_value=None)
    def test_adopt_untracked_completed_item_falls_back_to_generic_move(self, infer_mock, move_mock):
        moved = _adopt_untracked_completed_item({
            "name": "Random NZB Upload",
            "path": "C:\\tests\\completed\\Random NZB Upload",
        })

        self.assertEqual(moved, "C:\\tests\\library\\Random NZB Upload")
        infer_mock.assert_called_once()
        move_mock.assert_called_once_with({
            "name": "Random NZB Upload",
            "path": "C:\\tests\\completed\\Random NZB Upload",
        })

    @patch("app.downloads.manager._move_completed")
    @patch("app.downloads.manager._infer_update_info_from_completed_item", return_value=None)
    def test_adopt_untracked_completed_item_does_not_generic_move_update_like_download(self, infer_mock, move_mock):
        moved = _adopt_untracked_completed_item({
            "name": "Sample Package Update v1.25.0 TEST-GRP",
            "path": "C:\\tests\\completed\\Sample Package Update v1.25.0 TEST-GRP",
        })

        self.assertIsNone(moved)
        infer_mock.assert_called_once()
        move_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
