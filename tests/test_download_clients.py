import json
import ntpath
import os
import re
import unittest
from unittest.mock import patch

import app.downloads.manager as downloads_manager
from app.downloads.client import (
    get_download_client_diagnostics,
    get_download_client_capabilities,
    get_supported_download_clients,
    queue_download,
    remove_active_download,
    remove_completed_download,
)
from app.downloads.manager import (
    _check_completed,
    _adopt_untracked_completed_item,
    _build_pending_queue_item,
    _format_pending_label,
    _infer_pending_info_from_queue_item,
    _infer_update_info_from_completed_item,
    _iter_importable_download_files,
    _move_completed_with_reason,
    _normalize_imported_wrapped_files,
    _select_completed_update_candidate,
    _search_and_queue,
    filter_download_search_results,
    get_download_ui_visibility,
    get_active_downloads,
    get_downloads_state,
    manual_search_update,
    queue_download_url,
    dismiss_duplicate_download,
    remove_pending_download,
    remove_duplicate_download,
    search_update_options,
    sort_download_search_results,
)
from app.downloads.prowlarr import _normalize_result
from app.downloads.usenet_client import add_nzb, list_active, list_completed, list_history, remove_history, remove_queue_item
from app.downloads.usenet_client import _restrict_job_to_matching_update_files


def _normalize_fixture_path(value):
    text = str(value or "")
    if re.match(r"^[A-Za-z]:[\\/]", text) or "\\" in text:
        return text.replace("/", "\\")
    return os.path.normpath(text)


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

    def test_sort_download_search_results_orders_by_age_across_indexers(self):
        ordered = sort_download_search_results([
            {"title": "Example Old", "indexer": "Indexer B", "age_minutes": 21 * 24 * 60},
            {"title": "Example New", "indexer": "Indexer A", "age_minutes": 2 * 24 * 60},
            {"title": "Example Mid", "indexer": "Indexer C", "age_minutes": 7 * 24 * 60},
        ])

        self.assertEqual(
            [item["title"] for item in ordered],
            ["Example New", "Example Mid", "Example Old"],
        )

    def test_sort_download_search_results_places_missing_age_last(self):
        ordered = sort_download_search_results([
            {"title": "Example Unknown", "indexer": "Indexer A", "age_minutes": None},
            {"title": "Example Recent", "indexer": "Indexer B", "age_minutes": 60},
        ])

        self.assertEqual(
            [item["title"] for item in ordered],
            ["Example Recent", "Example Unknown"],
        )


class QueueRoutingTests(unittest.TestCase):
    def test_supported_download_clients_includes_torrent_and_usenet(self):
        supported = get_supported_download_clients()
        keys = {(item.get("protocol"), item.get("type")) for item in supported}
        self.assertIn(("torrent", "qbittorrent"), keys)
        self.assertIn(("torrent", "transmission"), keys)
        self.assertIn(("torrent", "deluge"), keys)
        self.assertIn(("torrent", "rtorrent"), keys)
        self.assertIn(("usenet", "sabnzbd"), keys)
        self.assertIn(("usenet", "nzbget"), keys)

    def test_get_download_client_capabilities_resolves_by_type_when_protocol_missing(self):
        caps = get_download_client_capabilities("", {"type": "rtorrent"})
        self.assertIsNotNone(caps)
        self.assertEqual(caps["protocol"], "torrent")
        self.assertEqual(caps["type"], "rtorrent")
        self.assertTrue(caps["supports_categories"])
        self.assertTrue(caps["supports_download_path"])
        self.assertTrue(caps["supports_live_status"])

    def test_get_download_client_capabilities_marks_pneumatic_without_live_status(self):
        caps = get_download_client_capabilities("usenet", {"type": "pneumatic"})
        self.assertIsNotNone(caps)
        self.assertEqual(caps["protocol"], "usenet")
        self.assertEqual(caps["type"], "pneumatic")
        self.assertFalse(caps["supports_live_status"])

    def test_get_download_client_diagnostics_reports_missing_required_fields(self):
        diag = get_download_client_diagnostics("", {"type": "rtorrent", "url": ""})
        self.assertTrue(diag["supported"])
        self.assertEqual(diag["protocol"], "torrent")
        self.assertEqual(diag["type"], "rtorrent")
        self.assertIn("url", diag["missing"])
        self.assertIn("username", diag["missing"])
        self.assertIn("password", diag["missing"])

    def test_get_download_client_diagnostics_for_deluge_does_not_require_username(self):
        diag = get_download_client_diagnostics("", {"type": "deluge", "url": "http://deluge.local", "password": "x"})
        self.assertTrue(diag["supported"])
        self.assertEqual(diag["missing"], [])

    def test_get_download_client_diagnostics_for_nzbget_requires_username_and_password(self):
        diag = get_download_client_diagnostics("", {"type": "nzbget", "url": "http://nzbget.local"})
        self.assertTrue(diag["supported"])
        self.assertEqual(diag["protocol"], "usenet")
        self.assertIn("username", diag["missing"])
        self.assertIn("password", diag["missing"])

    def test_get_download_ui_visibility_handles_all_protocol_configurations(self):
        cases = [
            (
                "both",
                {
                    "torrent_client": {"type": "qbittorrent", "url": "http://torrent.local"},
                    "usenet_client": {"type": "sabnzbd", "url": "http://sab.local", "api_key": "secret"},
                },
                {"show_protocol_column": True, "show_torrent_columns": True, "show_usenet_columns": True},
            ),
            (
                "torrent_only",
                {
                    "torrent_client": {"type": "qbittorrent", "url": "http://torrent.local"},
                    "usenet_client": {"type": "sabnzbd", "url": "http://sab.local"},
                },
                {"show_protocol_column": True, "show_torrent_columns": True, "show_usenet_columns": False},
            ),
            (
                "usenet_only",
                {
                    "torrent_client": {"type": "qbittorrent"},
                    "usenet_client": {"type": "sabnzbd", "url": "http://sab.local", "api_key": "secret"},
                },
                {"show_protocol_column": True, "show_torrent_columns": False, "show_usenet_columns": True},
            ),
            (
                "neither",
                {
                    "torrent_client": {"type": "qbittorrent"},
                    "usenet_client": {"type": "sabnzbd", "url": "http://sab.local"},
                },
                {"show_protocol_column": True, "show_torrent_columns": False, "show_usenet_columns": False},
            ),
        ]

        for label, downloads, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(get_download_ui_visibility(downloads), expected)

    @patch("app.downloads.manager.list_active_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager.load_settings")
    def test_get_active_downloads_reports_combined_summary_speed(
        self,
        load_settings_mock,
        poll_targets_mock,
        list_active_downloads_mock,
    ):
        load_settings_mock.return_value = {"downloads": {}}
        poll_targets_mock.return_value = [
            ("torrent", {"type": "qbittorrent"}),
            ("usenet", {"type": "sabnzbd"}),
        ]
        list_active_downloads_mock.side_effect = [
            [{
                "protocol": "torrent",
                "client_type": "qbittorrent",
                "name": "Example Torrent",
                "down_speed": 1000,
            }],
            [{
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "name": "Example NZB",
                "down_speed": None,
                "queue_down_speed": 2000,
            }],
        ]

        ok, message, items, summary = get_active_downloads()

        self.assertTrue(ok)
        self.assertIsNone(message)
        self.assertEqual(len(items), 2)
        self.assertEqual(summary["down_speed"], 3000)

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
    def test_queue_download_url_forwards_dlc_only_flag(self, load_settings_mock, queue_download_mock):
        load_settings_mock.return_value = {
            "downloads": {
                "torrent_client": {
                    "type": "rtorrent",
                    "url": "http://rtorrent.local",
                    "username": "user",
                    "password": "pass",
                },
            }
        }
        queue_download_mock.return_value = (True, "ok", "abc123")

        ok, message = queue_download_url(
            "magnet:?xt=urn:btih:abcdef",
            expected_name="Example DLC",
            dlc_only=True,
        )

        self.assertTrue(ok)
        self.assertEqual(message, "Queued download.")
        queue_download_mock.assert_called_once()
        self.assertTrue(queue_download_mock.call_args.kwargs["dlc_only"])

    @patch("app.downloads.client.add_torrent")
    @patch("app.downloads.client.resolve_download_url")
    def test_queue_download_forwards_resolved_torrent_content(self, resolve_download_url_mock, add_torrent_mock):
        resolve_download_url_mock.return_value = ("torrent_content", b"d8:announce5:testee")
        add_torrent_mock.return_value = (True, "ok", "abc123")

        ok, message, item_id = queue_download(
            "torrent",
            {
                "type": "qbittorrent",
                "url": "http://torrent.local",
                "username": "user",
                "password": "pass",
                "category": "aerofoil",
                "download_path": "X:\\fixture-root\\downloads",
            },
            "https://indexer.example/download/123",
        )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        self.assertEqual(item_id, "abc123")
        self.assertEqual(add_torrent_mock.call_args.kwargs["torrent_content"], b"d8:announce5:testee")

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

    @patch("app.downloads.usenet_client._delete_job")
    @patch("app.downloads.usenet_client._resume_job", return_value=False)
    @patch("app.downloads.usenet_client._restrict_job_to_matching_dlc_files", return_value=(True, None))
    @patch("app.downloads.usenet_client._sab_request")
    def test_add_nzb_fails_when_resume_fails_for_dlc_only(
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
            dlc_only=True,
        )

        self.assertFalse(ok)
        self.assertIn("failed to resume", message.lower())
        self.assertIsNone(item_id)
        restrict_mock.assert_called_once()
        resume_mock.assert_called_once()
        delete_job_mock.assert_called_once_with("http://sab.local", "secret", "nzo123", timeout_seconds=15)

    @patch("app.downloads.manager.queue_download")
    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager._get_local_known_update_version", return_value=196608)
    @patch("app.downloads.manager._get_highest_owned_update_version", return_value=196608)
    def test_queue_download_url_rejects_duplicate_update_before_queueing(
        self,
        highest_owned_mock,
        local_known_mock,
        load_settings_mock,
        queue_download_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "torrent_client": {
                    "type": "rtorrent",
                    "url": "http://rtorrent.local",
                    "username": "user",
                    "password": "pass",
                },
            }
        }

        ok, message = queue_download_url(
            "magnet:?xt=urn:btih:abcdef",
            expected_name="Example Title Update",
            update_only=True,
            expected_version=196608,
            title_id="0100EXAMPLE000000",
        )

        self.assertFalse(ok)
        self.assertEqual(message, "duplicate update: 0100EXAMPLE000000 v196608 already known (latest v196608)")
        queue_download_mock.assert_not_called()
        highest_owned_mock.assert_called_once_with("0100EXAMPLE000000")
        local_known_mock.assert_called_once_with("0100EXAMPLE000000")

    @patch("app.downloads.manager.pick_best_result")
    @patch("app.downloads.manager.ProwlarrClient")
    @patch("app.downloads.manager.titles_lib.get_game_info", return_value={"name": "Example Title"})
    @patch("app.downloads.manager.titles_lib.release_titledb")
    @patch("app.downloads.manager.titles_lib.load_titledb")
    @patch("app.downloads.manager.load_settings")
    def test_search_update_options_filters_results_to_configured_protocols(
        self,
        load_settings_mock,
        load_titledb_mock,
        release_titledb_mock,
        get_game_info_mock,
        prowlarr_client_mock,
        pick_best_result_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "prowlarr": {
                    "url": "http://prowlarr.local",
                    "api_key": "secret",
                },
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                },
            }
        }
        prowlarr_client_mock.return_value.search.return_value = [
            {"title": "Example Release Torrent", "protocol": "torrent", "download_url": "magnet:?xt=urn:btih:abcdef"},
            {"title": "Example Release NZB", "protocol": "usenet", "download_url": "https://indexer.example/file.nzb"},
        ]
        def pick_result(items, **kwargs):
            self.assertTrue(kwargs["require_exact_version"])
            self.assertEqual(kwargs["version"], 123)
            return items[0] if items[0].get("protocol") in (kwargs.get("allowed_protocols") or []) else None

        pick_best_result_mock.side_effect = pick_result

        ok, message, results = search_update_options("0100000000010000", 123, limit=20)

        self.assertTrue(ok)
        self.assertIsNone(message)
        self.assertEqual([item["protocol"] for item in results], ["usenet"])

    @patch("app.downloads.manager.pick_best_result")
    @patch("app.downloads.manager.ProwlarrClient")
    @patch("app.downloads.manager.titles_lib.get_game_info", return_value={"name": "Example Title"})
    @patch("app.downloads.manager.titles_lib.release_titledb")
    @patch("app.downloads.manager.titles_lib.load_titledb")
    @patch("app.downloads.manager.load_settings")
    def test_search_update_options_sorts_results_by_age_across_indexers(
        self,
        load_settings_mock,
        load_titledb_mock,
        release_titledb_mock,
        get_game_info_mock,
        prowlarr_client_mock,
        pick_best_result_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "prowlarr": {
                    "url": "http://prowlarr.local",
                    "api_key": "secret",
                },
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                },
            }
        }
        prowlarr_client_mock.return_value.search.return_value = [
            {
                "title": "Example Old",
                "protocol": "usenet",
                "download_url": "https://indexer-b.example/file.nzb",
                "indexer": "Indexer B",
                "age_minutes": 20 * 24 * 60,
                "age_label": "20 d",
            },
            {
                "title": "Example New",
                "protocol": "usenet",
                "download_url": "https://indexer-a.example/file.nzb",
                "indexer": "Indexer A",
                "age_minutes": 2 * 24 * 60,
                "age_label": "2 d",
            },
        ]
        pick_best_result_mock.side_effect = lambda items, **kwargs: items[0]

        ok, message, results = search_update_options("0100000000010000", 123, limit=20)

        self.assertTrue(ok)
        self.assertIsNone(message)
        self.assertEqual([item["title"] for item in results], ["Example New", "Example Old"])

    @patch("app.downloads.manager.queue_download")
    @patch("app.downloads.manager.pick_best_result")
    @patch("app.downloads.manager.ProwlarrClient")
    @patch("app.downloads.manager.titles_lib.get_game_info", return_value={"name": "Example Title"})
    @patch("app.downloads.manager.titles_lib.release_titledb")
    @patch("app.downloads.manager.titles_lib.load_titledb")
    @patch("app.downloads.manager.load_settings")
    def test_manual_search_update_allows_non_exact_version_match(
        self,
        load_settings_mock,
        load_titledb_mock,
        release_titledb_mock,
        get_game_info_mock,
        prowlarr_client_mock,
        pick_best_result_mock,
        queue_download_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "prowlarr": {
                    "url": "http://prowlarr.local",
                    "api_key": "secret",
                },
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                },
            }
        }
        prowlarr_client_mock.return_value.search.return_value = [
            {
                "title": "Example Title Update 1.1.10 NZB-GRP",
                "protocol": "usenet",
                "download_url": "https://indexer.example/file.nzb",
            }
        ]

        def pick_result(results, **kwargs):
            self.assertFalse(kwargs["require_exact_version"])
            return results[0]

        pick_best_result_mock.side_effect = pick_result
        queue_download_mock.return_value = (True, "ok", "nzo123")

        ok, message = manual_search_update("0100000000010000", 1245184)

        self.assertTrue(ok)
        self.assertEqual(message, "Queued download.")
        queue_download_mock.assert_called_once()

    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager.pick_best_result")
    def test_search_and_queue_requires_exact_version_by_default(self, pick_best_result_mock, load_settings_mock):
        load_settings_mock.return_value = {"downloads": {}}
        client = type("Client", (), {
            "search": lambda self, query, indexer_ids=None, categories=None, limit=None: [
                {"title": "Example Title Update [v1245184]", "protocol": "usenet", "download_url": "https://indexer.example/file.nzb"}
            ]
        })()

        def pick_result(results, **kwargs):
            self.assertTrue(kwargs["require_exact_version"])
            return None

        pick_best_result_mock.side_effect = pick_result

        ok, message = _search_and_queue(
            client=client,
            update={"title_id": "0100000000010000", "title_name": "Example Title", "version": 1245184},
            downloads={},
            indexer_ids=[],
            categories=[],
            required_terms=[],
            blacklist_terms=[],
            min_seeders=0,
            min_age_minutes=0,
            search_limit=10,
            allowed_protocols=["usenet"],
        )

        self.assertFalse(ok)
        self.assertEqual(message, "No matching results found.")

    @patch("app.downloads.manager.queue_download")
    @patch("app.downloads.manager._get_local_known_update_version", return_value=196608)
    @patch("app.downloads.manager._get_highest_owned_update_version", return_value=196608)
    def test_search_and_queue_rejects_duplicate_update_before_searching(
        self,
        highest_owned_mock,
        local_known_mock,
        queue_download_mock,
    ):
        ok, message = _search_and_queue(
            client=object(),
            update={"title_id": "0100EXAMPLE000000", "title_name": "Example Title", "version": 196608},
            downloads={},
            indexer_ids=[],
            categories=[],
            required_terms=[],
            blacklist_terms=[],
            min_seeders=0,
            min_age_minutes=0,
            search_limit=10,
            allowed_protocols=["usenet"],
        )

        self.assertFalse(ok)
        self.assertEqual(message, "duplicate update: 0100EXAMPLE000000 v196608 already known (latest v196608)")
        queue_download_mock.assert_not_called()
        highest_owned_mock.assert_called_once_with("0100EXAMPLE000000")
        local_known_mock.assert_called_once_with("0100EXAMPLE000000")

    def test_filter_download_search_results_excludes_unconfigured_protocols(self):
        results = [
            {"title": "Example Torrent", "protocol": "torrent", "seeders": 50},
            {"title": "Example NZB", "protocol": "usenet", "age_minutes": 120},
        ]

        filtered = filter_download_search_results(results, {
            "usenet_client": {
                "type": "sabnzbd",
                "url": "http://sab.local",
                "api_key": "secret",
            }
        })

        self.assertEqual([item["protocol"] for item in filtered], ["usenet"])

    def test_format_pending_label_falls_back_to_expected_name_for_manual_items(self):
        self.assertEqual(
            _format_pending_label({
                "title_id": None,
                "version": None,
                "expected_name": "Example Release NSW-GRP",
            }),
            "Example Release NSW-GRP",
        )

    def test_build_pending_queue_item_prefers_completed_name_for_stuck_entries(self):
        info = {
            "title_id": "0100000000010000",
            "version": 123,
            "hash": "nzo123",
            "id": "nzo123",
            "expected_name": "Example Release NSW-GRP",
            "title_name": "Example Title",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "state": "stuck",
            "state_reason": "move failed",
            "last_seen_status": "Completed",
            "last_seen_path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        }
        snapshot = {
            "active_by_protocol": {},
            "completed_by_protocol": {
                "usenet": {
                    "items": [{
                        "id": "nzo123",
                        "hash": "nzo123",
                        "name": "Example Release NSW-GRP",
                        "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
                    }],
                },
            },
        }

        item = _build_pending_queue_item("0100000000010000:123", info, snapshot)

        self.assertEqual(item["label"], "Example Release NSW-GRP")
        self.assertEqual(item["state"], "stuck")
        self.assertEqual(item["state_reason"], "move failed")

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
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": None,
            }
        },
        "completed": set(),
    })
    @patch("app.downloads.manager._get_completed_poll_targets", return_value=[])
    @patch("app.downloads.manager.load_settings", return_value={"downloads": {}})
    def test_get_downloads_state_exposes_label_for_manual_pending_items(
        self,
        load_settings_mock,
        poll_targets_mock,
        _state_lock_mock,
    ):
        state = get_downloads_state()

        self.assertEqual(state["pending"][0]["label"], "Example Release NSW-GRP")
        self.assertEqual(state["pending"][0]["expected_name"], "Example Release NSW-GRP")
        self.assertIsNone(state["pending"][0]["title_id"])
        self.assertIsNone(state["pending"][0]["version"])
        self.assertEqual(state["pending"][0]["state"], "queued")
        self.assertTrue(state["pending"][0]["deletable"])

    @patch("app.downloads.manager.list_active_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 123.0,
        "pending": {},
        "completed": set(),
    })
    def test_get_downloads_state_restores_pending_items_from_active_queue(
        self,
        _state_lock_mock,
        load_settings_mock,
        poll_targets_mock,
        list_active_downloads_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "torrent_client": {
                    "type": "qbittorrent",
                    "url": "http://torrent.local",
                    "category": "aerofoil",
                }
            }
        }
        poll_targets_mock.return_value = [("torrent", {"type": "qbittorrent", "category": "aerofoil"})]
        list_active_downloads_mock.return_value = [{
            "id": "ABC123",
            "hash": "ABC123",
            "protocol": "torrent",
            "client_type": "qbittorrent",
            "name": "Example Release NSW-GRP",
        }]

        state = get_downloads_state()

        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["id"], "abc123")
        self.assertEqual(state["pending"][0]["label"], "Example Release NSW-GRP")
        self.assertEqual(state["pending"][0]["protocol"], "torrent")

    @patch("app.downloads.manager._infer_pending_info_from_queue_item")
    @patch("app.downloads.manager.list_history_downloads")
    @patch("app.downloads.manager.list_active_downloads", return_value=[])
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 123.0,
        "pending": {},
        "completed": set(),
    })
    def test_get_downloads_state_restores_pending_items_from_completed_queue(
        self,
        _state_lock_mock,
        load_settings_mock,
        poll_targets_mock,
        list_active_mock,
        list_history_mock,
        infer_pending_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                }
            }
        }
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd", "category": "aerofoil"})]
        list_history_mock.return_value = [{
            "id": "nzo123",
            "hash": "nzo123",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "name": "Example DLC Release",
            "path": "X:\\fixture-root\\incoming\\Example DLC Release",
        }]
        infer_pending_mock.return_value = {
            "title_id": "010086B00BB50000",
            "app_id": None,
            "app_type": "DLC",
            "version": 0,
            "hash": "nzo123",
            "id": "nzo123",
            "expected_name": "Example DLC Release",
            "title_name": "Example Title",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "state": "queued",
            "state_reason": None,
            "last_seen_status": None,
            "last_seen_path": "X:\\fixture-root\\incoming\\Example DLC Release",
        }

        state = get_downloads_state()

        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["id"], "nzo123")
        self.assertEqual(state["pending"][0]["app_type"], "DLC")
        self.assertEqual(state["pending"][0]["state"], "completed")
        self.assertEqual(state["pending"][0]["label"], "Example DLC Release")

    @patch("app.downloads.manager._infer_pending_info_from_queue_item")
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager.list_active_downloads", return_value=[])
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 123.0,
        "pending": {},
        "completed": set(),
        "completed_identities": set(),
    })
    def test_get_downloads_state_does_not_restore_pending_items_from_completed_torrent_queue(
        self,
        _state_lock_mock,
        load_settings_mock,
        poll_targets_mock,
        list_active_mock,
        list_history_mock,
        infer_pending_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "torrent_client": {
                    "type": "qbittorrent",
                    "url": "http://torrent.local",
                    "category": "aerofoil",
                }
            }
        }
        poll_targets_mock.return_value = [("torrent", {"type": "qbittorrent", "category": "aerofoil"})]
        list_history_mock.return_value = [{
            "id": "ABC123",
            "hash": "ABC123",
            "protocol": "torrent",
            "client_type": "qbittorrent",
            "name": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        }]

        state = get_downloads_state()

        self.assertEqual(state["pending"], [])
        infer_pending_mock.assert_not_called()

    @patch("app.downloads.manager._infer_pending_info_from_queue_item")
    @patch("app.downloads.manager.list_history_downloads")
    @patch("app.downloads.manager.list_active_downloads", return_value=[])
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 123.0,
        "pending": {},
        "completed": {"0100000000010000:123"},
        "completed_identities": {("usenet", "sabnzbd", "nzo123")},
    })
    def test_get_downloads_state_skips_restoring_completed_items_already_seen_by_identity(
        self,
        _state_lock_mock,
        load_settings_mock,
        poll_targets_mock,
        list_active_mock,
        list_history_mock,
        infer_pending_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                }
            }
        }
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd", "category": "aerofoil"})]
        list_history_mock.return_value = [{
            "id": "nzo123",
            "hash": "nzo123",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "name": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        }]

        state = get_downloads_state()

        self.assertEqual(state["pending"], [])
        infer_pending_mock.assert_not_called()

    @patch("app.downloads.manager.list_history_downloads")
    @patch("app.downloads.manager.list_active_downloads", return_value=[])
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 123.0,
        "pending": {
            "0100000000010000:123": {
                "title_id": "0100000000010000",
                "version": 123,
                "hash": "nzo123",
                "id": "nzo123",
                "expected_name": "Example Release NSW-GRP",
                "title_name": "Example Title",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "stuck",
                "state_reason": "move failed",
                "last_seen_status": "Completed",
                "last_seen_path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
            }
        },
        "completed": set(),
    })
    def test_get_downloads_state_prefers_download_name_for_stuck_items(
        self,
        _state_lock_mock,
        load_settings_mock,
        poll_targets_mock,
        list_active_mock,
        list_history_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                }
            }
        }
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd", "category": "aerofoil"})]
        list_history_mock.return_value = [{
            "id": "nzo123",
            "hash": "nzo123",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "name": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        }]

        state = get_downloads_state()

        self.assertEqual(state["pending"][0]["label"], "Example Release NSW-GRP")

    @patch("app.downloads.manager.list_history_downloads")
    @patch("app.downloads.manager.list_active_downloads", return_value=[])
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 123.0,
        "pending": {
            "0100000000010000:123": {
                "title_id": "0100000000010000",
                "version": 123,
                "hash": "nzo123",
                "id": "nzo123",
                "expected_name": "Example Failed Release",
                "title_name": "Example Title",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": None,
            }
        },
        "completed": set(),
    })
    def test_get_downloads_state_marks_sab_failed_history_items_as_failed(
        self,
        _state_lock_mock,
        load_settings_mock,
        poll_targets_mock,
        list_active_mock,
        list_history_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                }
            }
        }
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd", "category": "aerofoil"})]
        list_history_mock.return_value = [{
            "id": "nzo123",
            "hash": "nzo123",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "name": "Example Failed Release",
            "status": "Failed",
            "state": "failed",
            "state_reason": "Unpack failed",
            "path": "",
        }]

        state = get_downloads_state()

        self.assertEqual(state["pending"][0]["state"], "failed")
        self.assertEqual(state["pending"][0]["state_reason"], "Unpack failed")
        self.assertEqual(state["pending"][0]["label"], "Example Failed Release")

    @patch("app.downloads.manager.list_history_downloads", return_value=[])
    @patch("app.downloads.manager.list_active_downloads", return_value=[])
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager.load_settings")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 123.0,
        "pending": {
            "010040600C5CE000:655360": {
                "title_id": "010040600C5CE000",
                "version": 655360,
                "hash": "nzo456",
                "id": "nzo456",
                "expected_name": "Example Title Update v3.2.0 INTERNAL NSW-GRP",
                "title_name": "Example Title",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": None,
            }
        },
        "completed": set(),
    })
    def test_get_downloads_state_prefers_download_name_for_inactive_queued_items(
        self,
        _state_lock_mock,
        load_settings_mock,
        poll_targets_mock,
        list_active_mock,
        list_history_mock,
    ):
        load_settings_mock.return_value = {
            "downloads": {
                "usenet_client": {
                    "type": "sabnzbd",
                    "url": "http://sab.local",
                    "api_key": "secret",
                    "category": "aerofoil",
                }
            }
        }
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd", "category": "aerofoil"})]

        state = get_downloads_state()

        self.assertEqual(
            state["pending"][0]["label"],
            "Example Title Update v3.2.0 INTERNAL NSW-GRP",
        )

    @patch("app.downloads.manager._infer_content_info_from_completed_item")
    def test_infer_pending_info_from_queue_item_uses_completed_content_metadata(self, infer_content_mock):
        infer_content_mock.return_value = {
            "title_id": "010086B00BB50000",
            "app_id": "010086B00BB51007",
            "app_type": "DLC",
            "title_name": "Example Title",
            "version": 0,
        }

        info = _infer_pending_info_from_queue_item({
            "id": "nzo123",
            "hash": "nzo123",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "name": "Example Title DLC Pack",
            "path": "X:\\fixture-root\\incoming\\Example Title DLC Pack",
        })

        self.assertEqual(info["title_id"], "010086B00BB50000")
        self.assertEqual(info["app_id"], "010086B00BB51007")
        self.assertEqual(info["app_type"], "DLC")
        self.assertEqual(info["version"], 0)
        self.assertEqual(info["expected_name"], "Example Title DLC Pack")

    @patch("app.downloads.manager._infer_content_info_from_completed_item")
    def test_infer_pending_info_from_queue_item_does_not_copy_base_version(self, infer_content_mock):
        infer_content_mock.return_value = {
            "title_id": "0100000000010000",
            "app_id": "0100000000010000",
            "app_type": "BASE",
            "title_name": "Example Title",
            "version": 65536,
        }

        info = _infer_pending_info_from_queue_item({
            "id": "abc123",
            "hash": "abc123",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "name": "Example Title BASE",
            "path": "X:\\fixture-root\\incoming\\Example Title BASE",
        })

        self.assertEqual(info["title_id"], "0100000000010000")
        self.assertEqual(info["app_type"], "BASE")
        self.assertIsNone(info["version"])
        self.assertEqual(info["expected_name"], "Example Title BASE")

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

    @patch("app.downloads.client.add_torrent")
    def test_queue_download_routes_by_client_type_when_protocol_missing(self, add_torrent_mock):
        add_torrent_mock.return_value = (True, "ok", "abc123")

        ok, message, item_id = queue_download(
            "",
            {
                "type": "qbittorrent",
                "url": "http://torrent.local",
                "username": "user",
                "password": "pass",
                "category": "aerofoil",
                "download_path": "X:\\fixture-root\\downloads",
            },
            "magnet:?xt=urn:btih:abcdef",
            expected_name="Game Update",
            update_only=True,
            exclude_russian=True,
            expected_version=123,
        )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        self.assertEqual(item_id, "abc123")
        add_torrent_mock.assert_called_once()
        self.assertEqual(add_torrent_mock.call_args.kwargs["client_type"], "qbittorrent")

    @patch("app.downloads.client.add_nzbget")
    def test_queue_download_routes_to_nzbget_when_client_type_is_nzbget(self, add_nzbget_mock):
        add_nzbget_mock.return_value = (True, "ok", "42")

        ok, message, item_id = queue_download(
            protocol="",
            client_cfg={
                "type": "nzbget",
                "url": "http://nzbget.local",
                "username": "user",
                "password": "pass",
                "category": "aerofoil",
            },
            download_url="https://indexer.example/file.nzb",
        )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        self.assertEqual(item_id, "42")
        add_nzbget_mock.assert_called_once()
        self.assertNotIn("download_path", add_nzbget_mock.call_args.kwargs)
        self.assertFalse(add_nzbget_mock.call_args.kwargs["update_only"])


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

    @patch("app.downloads.usenet_client._delete_job_files", return_value=True)
    @patch("app.downloads.usenet_client._get_job_files")
    def test_restrict_job_matches_semantic_version_when_internal_tag_missing(self, get_job_files_mock, delete_job_files_mock):
        get_job_files_mock.return_value = [
            {"filename": "Game Update 1.0.0.nsp", "nzf_id": "1"},
            {"filename": "Game Update 1.1.0.nsp", "nzf_id": "2"},
        ]

        ok, message = _restrict_job_to_matching_update_files(
            "http://sab.local",
            "secret",
            "nzo123",
            expected_version=65792,
        )

        self.assertTrue(ok)
        self.assertIsNone(message)
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
    def test_list_active_exposes_queue_speed_only_in_summary_metadata(self, sab_request_mock):
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
        self.assertIsNone(items[0]["down_speed"])
        self.assertEqual(items[0]["queue_down_speed"], int(512.5 * 1024))

    @patch("app.downloads.usenet_client._sab_request")
    def test_list_active_does_not_duplicate_queue_speed_across_multiple_items(self, sab_request_mock):
        sab_request_mock.return_value = {
            "queue": {
                "kbpersec": "512.5",
                "slots": [
                    {
                        "nzo_id": "nzo123",
                        "filename": "Example Base",
                        "status": "Downloading",
                        "mb": "100",
                        "mbleft": "50",
                        "timeleft": "00:10:00",
                        "cat": "aerofoil",
                    },
                    {
                        "nzo_id": "nzo456",
                        "filename": "Example Update",
                        "status": "Downloading",
                        "mb": "20",
                        "mbleft": "10",
                        "timeleft": "00:02:00",
                        "cat": "aerofoil",
                    },
                ],
            }
        }

        items = list_active("http://sab.local", "secret", category="aerofoil")

        self.assertEqual(len(items), 2)
        self.assertIsNone(items[0]["down_speed"])
        self.assertIsNone(items[1]["down_speed"])
        self.assertEqual(items[0]["queue_down_speed"], int(512.5 * 1024))
        self.assertEqual(items[1]["queue_down_speed"], int(512.5 * 1024))

    @patch("app.downloads.usenet_client._sab_request")
    def test_list_completed_ignores_shared_completed_dir_rows(self, sab_request_mock):
        sab_request_mock.return_value = {
            "history": {
                "completed_dir": "D:\\Downloads\\Complete",
                "slots": [
                    {
                        "nzo_id": "nzo123",
                        "status": "Completed",
                        "category": "aerofoil",
                        "storage": "D:\\Downloads\\Complete",
                        "name": "Shared Root",
                    }
                ],
            }
        }

        items = list_completed("http://sab.local", "secret", category="aerofoil")

        self.assertEqual(items, [])

    @patch("app.downloads.usenet_client._sab_request")
    def test_list_completed_keeps_job_subdirectories_under_completed_dir(self, sab_request_mock):
        sab_request_mock.return_value = {
            "history": {
                "completed_dir": "D:\\Downloads\\Complete",
                "slots": [
                    {
                        "nzo_id": "nzo123",
                        "status": "Completed",
                        "category": "aerofoil",
                        "storage": "D:\\Downloads\\Complete\\Example Release",
                        "name": "Example Release",
                    }
                ],
            }
        }

        items = list_completed("http://sab.local", "secret", category="aerofoil")

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["path"], "D:\\Downloads\\Complete\\Example Release")

    @patch("app.downloads.usenet_client._sab_request")
    def test_list_completed_can_include_failed_history_rows_for_queue_state(self, sab_request_mock):
        sab_request_mock.return_value = {
            "history": {
                "completed_dir": "D:\\Downloads\\Complete",
                "slots": [
                    {
                        "nzo_id": "nzo789",
                        "status": "Failed",
                        "category": "aerofoil",
                        "storage": "",
                        "name": "Example Failed Release",
                        "fail_message": "Unpack failed",
                    }
                ],
            }
        }

        items = list_history(
            "http://sab.local",
            "secret",
            category="aerofoil",
        )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "nzo789")
        self.assertEqual(items[0]["state"], "failed")
        self.assertEqual(items[0]["state_reason"], "Unpack failed")

    @patch("app.downloads.usenet_client._sab_request")
    def test_list_completed_excludes_failed_history_rows_by_default(self, sab_request_mock):
        sab_request_mock.return_value = {
            "history": {
                "completed_dir": "D:\\Downloads\\Complete",
                "slots": [
                    {
                        "nzo_id": "nzo789",
                        "status": "Failed",
                        "category": "aerofoil",
                        "name": "Example Failed Release",
                    }
                ],
            }
        }

        items = list_completed("http://sab.local", "secret", category="aerofoil")

        self.assertEqual(items, [])


class DownloadRemovalRoutingTests(unittest.TestCase):
    @patch("app.downloads.client.remove_torrent")
    def test_remove_active_download_forwards_delete_files_to_torrent_clients(self, remove_torrent_mock):
        remove_torrent_mock.return_value = (True, "ok")

        ok, message = remove_active_download(
            "torrent",
            {
                "type": "qbittorrent",
                "url": "http://torrent.local",
                "username": "user",
                "password": "pass",
            },
            "abc123",
            delete_files=True,
        )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        remove_torrent_mock.assert_called_once()
        self.assertTrue(remove_torrent_mock.call_args.kwargs["delete_files"])

    @patch("app.downloads.client.remove_queue_item")
    def test_remove_active_download_routes_to_sab_queue_delete(self, remove_queue_item_mock):
        remove_queue_item_mock.return_value = (True, "ok")

        ok, message = remove_active_download(
            "usenet",
            {
                "type": "sabnzbd",
                "url": "http://sab.local",
                "api_key": "secret",
            },
            "nzo123",
            delete_files=True,
        )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        remove_queue_item_mock.assert_called_once()
        self.assertTrue(remove_queue_item_mock.call_args.kwargs["delete_files"])

    @patch("app.downloads.client.remove_history")
    def test_remove_completed_download_routes_to_sab_history_delete(self, remove_history_mock):
        remove_history_mock.return_value = (True, "ok")

        ok, message = remove_completed_download(
            "usenet",
            {
                "type": "sabnzbd",
                "url": "http://sab.local",
                "api_key": "secret",
            },
            "nzo123",
            delete_files=True,
        )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        remove_history_mock.assert_called_once()
        self.assertTrue(remove_history_mock.call_args.kwargs["delete_files"])

    @patch("app.downloads.usenet_client._sab_request")
    def test_remove_history_requests_file_deletion(self, sab_request_mock):
        sab_request_mock.return_value = {"status": True}

        ok, message = remove_history("http://sab.local", "secret", "nzo123", delete_files=True)

        self.assertTrue(ok)
        self.assertEqual(message, "SABnzbd history entry removed.")
        self.assertEqual(sab_request_mock.call_args.kwargs["del_files"], 1)

    @patch("app.downloads.usenet_client._sab_request")
    def test_remove_queue_item_requests_file_deletion(self, sab_request_mock):
        sab_request_mock.return_value = {"status": True}

        ok, message = remove_queue_item("http://sab.local", "secret", "nzo123", delete_files=True)

        self.assertTrue(ok)
        self.assertEqual(message, "SABnzbd queue item removed.")
        self.assertEqual(sab_request_mock.call_args.kwargs["del_files"], 1)


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
            [_normalize_fixture_path(path) for path in _iter_importable_download_files("X:\\fixture-root\\Example Release NSW-GRP")],
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
        self.assertEqual(tuple(_normalize_fixture_path(part) for part in move_mock.call_args_list[0].args), (
            "X:\\fixture-root\\Example Release NSW-GRP\\base.nsp.hdf",
            "X:\\fixture-root\\Example Release NSW-GRP\\base.nsp",
        ))
        self.assertEqual(tuple(_normalize_fixture_path(part) for part in move_mock.call_args_list[1].args), (
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

    @patch("app.downloads.manager.shutil.move")
    @patch("app.downloads.manager._ensure_unique_path", side_effect=lambda path: path)
    @patch("app.downloads.manager.os.path.isdir", return_value=False)
    @patch("app.downloads.manager.os.path.isfile", return_value=True)
    @patch("app.downloads.manager.os.path.exists", return_value=True)
    def test_normalize_imported_wrapped_xci_file_strips_hdf(
        self,
        exists_mock,
        isfile_mock,
        isdir_mock,
        ensure_unique_path_mock,
        move_mock,
    ):
        result = _normalize_imported_wrapped_files("X:\\fixture-root\\incoming\\example-base.xci.hdf")

        self.assertEqual(result, "X:\\fixture-root\\incoming\\example-base.xci")
        move_mock.assert_called_once_with(
            "X:\\fixture-root\\incoming\\example-base.xci.hdf",
            "X:\\fixture-root\\incoming\\example-base.xci",
        )

    @patch("app.downloads.manager.enqueue_organize_paths")
    @patch("app.downloads.manager.enqueue_cleanup_roots")
    @patch("app.downloads.manager.remove_completed_download", return_value=(True, "ok"))
    @patch("app.downloads.manager._move_completed_with_reason", return_value=("X:\\fixture-root\\Example Title [0100]\\Example Base.nsp", None))
    @patch("app.downloads.manager.list_active_downloads")
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
        list_active_mock,
        move_completed_mock,
        remove_completed_mock,
        enqueue_cleanup_roots_mock,
        enqueue_paths_mock,
    ):
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd"})]
        list_active_mock.return_value = []
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
    @patch("app.downloads.manager._move_completed_with_reason", return_value=("X:\\fixture-root\\Example Release NSW-GRP", None))
    @patch("app.downloads.manager.list_active_downloads")
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
        list_active_mock,
        move_completed_mock,
        remove_completed_mock,
        enqueue_cleanup_roots_mock,
        enqueue_paths_mock,
        isdir_mock,
    ):
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd"})]
        list_active_mock.return_value = []
        list_completed_mock.return_value = [{
            "id": "item-123",
            "hash": "item-123",
            "name": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        }]

        _check_completed({})

        enqueue_paths_mock.assert_called_once_with(["X:\\fixture-root\\Example Release NSW-GRP"])
        enqueue_cleanup_roots_mock.assert_called_once_with(["X:\\fixture-root\\Example Release NSW-GRP"])

    @patch("app.downloads.manager.enqueue_organize_paths")
    @patch("app.downloads.manager.enqueue_cleanup_roots")
    @patch("app.downloads.manager.remove_completed_download", return_value=(True, "ok"))
    @patch("app.downloads.manager._move_completed_with_reason")
    @patch("app.downloads.manager.list_active_downloads")
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {},
        "completed": set(),
    })
    def test_check_completed_does_not_adopt_untracked_torrent_items(
        self,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
        list_active_mock,
        move_completed_mock,
        remove_completed_mock,
        enqueue_cleanup_roots_mock,
        enqueue_paths_mock,
    ):
        poll_targets_mock.return_value = [("torrent", {"type": "qbittorrent"})]
        list_active_mock.return_value = []
        move_completed_mock.return_value = (None, "move failed")
        list_completed_mock.return_value = [{
            "hash": "torrent-123",
            "name": "Unrelated Existing Torrent",
            "path": "X:\\fixture-root\\incoming\\Unrelated Existing Torrent",
            "protocol": "torrent",
            "client_type": "qbittorrent",
        }]

        _check_completed({})

        move_completed_mock.assert_not_called()
        remove_completed_mock.assert_not_called()
        enqueue_paths_mock.assert_not_called()
        enqueue_cleanup_roots_mock.assert_not_called()

    @patch("app.downloads.manager.enqueue_organize_paths")
    @patch("app.downloads.manager.enqueue_cleanup_roots")
    @patch("app.downloads.manager.remove_completed_download", return_value=(True, "ok"))
    @patch("app.downloads.manager._move_completed_with_reason", return_value=("X:\\fixture-root\\Example Title [0100]\\Example Base.nsp", None))
    @patch("app.downloads.manager.list_active_downloads")
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {},
        "completed": set(),
    })
    def test_check_completed_restores_pending_items_from_active_queue_before_matching(
        self,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
        list_active_mock,
        move_completed_mock,
        remove_completed_mock,
        enqueue_cleanup_roots_mock,
        enqueue_paths_mock,
    ):
        poll_targets_mock.return_value = [("torrent", {"type": "qbittorrent", "category": "aerofoil"})]
        list_active_mock.return_value = [{
            "id": "ABC123",
            "hash": "ABC123",
            "protocol": "torrent",
            "client_type": "qbittorrent",
            "name": "Example Release NSW-GRP",
        }]
        list_completed_mock.return_value = [{
            "id": "ABC123",
            "hash": "abc123",
            "protocol": "torrent",
            "client_type": "qbittorrent",
            "name": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        }]

        _check_completed({})

        move_completed_mock.assert_called_once()
        remove_completed_mock.assert_called_once_with("torrent", {"type": "qbittorrent", "category": "aerofoil"}, "ABC123")
        enqueue_paths_mock.assert_called_once_with(["X:\\fixture-root\\Example Title [0100]\\Example Base.nsp"])
        enqueue_cleanup_roots_mock.assert_called_once_with([])

    @patch("app.downloads.manager.enqueue_organize_paths")
    @patch("app.downloads.manager.enqueue_cleanup_roots")
    @patch("app.downloads.manager.remove_completed_download")
    @patch("app.downloads.manager._move_completed_with_reason", return_value=("X:\\fixture-root\\Example Title [0100]\\Example Base.nsp", None))
    @patch("app.downloads.manager.list_active_downloads")
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {},
        "completed": set(),
    })
    def test_check_completed_keeps_torrent_seeding_when_configured(
        self,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
        list_active_mock,
        move_completed_mock,
        remove_completed_mock,
        enqueue_cleanup_roots_mock,
        enqueue_paths_mock,
    ):
        poll_targets_mock.return_value = [("torrent", {"type": "qbittorrent", "category": "aerofoil", "remove_completed_torrents_on_finish": False})]
        list_active_mock.return_value = [ {
            "id": "ABC123",
            "hash": "ABC123",
            "protocol": "torrent",
            "client_type": "qbittorrent",
            "name": "Example Release NSW-GRP",
        } ]
        list_completed_mock.return_value = [ {
            "id": "ABC123",
            "hash": "abc123",
            "protocol": "torrent",
            "client_type": "qbittorrent",
            "name": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Release NSW-GRP",
        } ]

        _check_completed({})

        move_completed_mock.assert_called_once()
        self.assertTrue(move_completed_mock.call_args.kwargs["copy_files"])
        remove_completed_mock.assert_not_called()
        enqueue_paths_mock.assert_called_once_with(["X:\\fixture-root\\Example Title [0100]\\Example Base.nsp"])
        enqueue_cleanup_roots_mock.assert_called_once_with([])

    @patch("app.downloads.manager._cleanup_download_path")
    @patch("app.downloads.manager._normalize_imported_wrapped_files", side_effect=lambda path: path)
    @patch("app.downloads.manager._build_generic_import_destination", return_value="X:\\library\\Example Base.nsp")
    @patch("app.downloads.manager.shutil.copy2")
    @patch("app.downloads.manager.shutil.move")
    @patch("app.downloads.manager._iter_importable_download_files", return_value=["C:\\tests\\completed\\Example Base.nsp"])
    def test_retained_torrent_import_copies_files_without_cleaning_source(
        self,
        importable_files_mock,
        move_mock,
        copy_mock,
        build_destination_mock,
        normalize_mock,
        cleanup_mock,
    ):
        moved_path, reason = downloads_manager._move_generic_importable_files(
            "C:\\tests\\completed\\Example Release",
            "X:\\library",
            copy_files=True,
        )

        self.assertEqual(moved_path, "X:\\library\\Example Base.nsp")
        self.assertIsNone(reason)
        copy_mock.assert_called_once_with("C:\\tests\\completed\\Example Base.nsp", "X:\\library\\Example Base.nsp")
        move_mock.assert_not_called()
        cleanup_mock.assert_not_called()

    @patch("app.downloads.manager.enqueue_organize_paths")
    @patch("app.downloads.manager.enqueue_cleanup_roots")
    @patch("app.downloads.manager.remove_completed_download", return_value=(True, "ok"))
    @patch("app.downloads.manager._move_completed_with_reason", return_value=("X:\\fixture-root\\Example Title [0100]\\Updates\\v1245184\\Example Title.nsp", None))
    @patch("app.downloads.manager._infer_update_info_from_completed_item")
    @patch("app.downloads.manager.list_active_downloads", return_value=[])
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "restored:usenet:sabnzbd:SABnzbd_nzo_2goo76g2": {
                "title_id": None,
                "version": None,
                "hash": "SABnzbd_nzo_2goo76g2",
                "id": "SABnzbd_nzo_2goo76g2",
                "expected_name": "Example Title Update v1.1.10 TEST-GRP",
                "title_name": "Example Title Update v1.1.10 TEST-GRP",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": "Downloading",
                "last_seen_path": None,
            }
        },
        "completed": set(),
    })
    def test_check_completed_infers_update_info_for_restored_pending_usenet_item(
        self,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
        list_active_mock,
        infer_update_info_mock,
        move_completed_with_reason_mock,
        remove_completed_mock,
        enqueue_cleanup_roots_mock,
        enqueue_paths_mock,
    ):
        infer_update_info_mock.return_value = {
            "title_id": "0100B6E012EBE000",
            "title_name": "Example Title",
            "version": 1245184,
        }
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd", "category": "aerofoil"})]
        list_completed_mock.return_value = [{
            "id": "SABnzbd_nzo_2goo76g2",
            "hash": "SABnzbd_nzo_2goo76g2",
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "name": "Example Title Update v1.1.10 TEST-GRP",
            "path": "X:\\fixture-root\\incoming\\Example Title Update v1.1.10 TEST-GRP",
        }]

        _check_completed({})

        infer_update_info_mock.assert_called_once()
        moved_item, moved_info = move_completed_with_reason_mock.call_args.args
        self.assertEqual(moved_item["id"], "SABnzbd_nzo_2goo76g2")
        self.assertEqual(moved_info["title_id"], "0100B6E012EBE000")
        self.assertEqual(moved_info["version"], 1245184)
        remove_completed_mock.assert_called_once_with("usenet", {"type": "sabnzbd", "category": "aerofoil"}, "SABnzbd_nzo_2goo76g2")
        enqueue_paths_mock.assert_called_once_with(["X:\\fixture-root\\Example Title [0100]\\Updates\\v1245184\\Example Title.nsp"])
        enqueue_cleanup_roots_mock.assert_called_once_with([])

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

    @patch("app.downloads.manager._move_completed_with_reason", return_value=("C:\\tests\\library\\Example Title Update", None))
    @patch("app.downloads.manager._infer_update_info_from_completed_item", return_value=None)
    def test_adopt_untracked_completed_usenet_update_falls_back_to_generic_move(self, infer_mock, move_completed_with_reason_mock):
        moved = _adopt_untracked_completed_item({
            "name": "Example Title Update v3.2.0 TEST-GRP",
            "path": "C:\\tests\\completed\\Example Title Update v3.2.0 TEST-GRP",
            "protocol": "usenet",
            "client_type": "sabnzbd",
        })

        self.assertEqual(moved, "C:\\tests\\library\\Example Title Update")
        infer_mock.assert_called_once()
        move_completed_with_reason_mock.assert_called_once_with({
            "name": "Example Title Update v3.2.0 TEST-GRP",
            "path": "C:\\tests\\completed\\Example Title Update v3.2.0 TEST-GRP",
            "protocol": "usenet",
            "client_type": "sabnzbd",
        })


class ManagedCompletionStateTests(unittest.TestCase):
    @patch("app.downloads.manager.os.path.getsize", return_value=100)
    @patch("app.downloads.manager._iter_completed_files")
    def test_select_completed_update_candidate_ignores_rar_archives(
        self,
        completed_files_mock,
        getsize_mock,
    ):
        archive_path = "C:\\tests\\completed\\Example Update v65536.rar"
        payload_path = "C:\\tests\\completed\\Example Update v65536.nsp"
        completed_files_mock.return_value = [archive_path, payload_path]

        path, version = _select_completed_update_candidate("C:\\tests\\completed")

        self.assertEqual(path, payload_path)
        self.assertEqual(version, 65536)

    @patch("app.downloads.manager._select_completed_update_candidate")
    @patch("app.downloads.manager._move_generic_importable_files", return_value=("X:\\library\\Example Title [BASE].nsp", None))
    @patch("app.downloads.manager.get_libraries_path", return_value=["X:\\library"])
    @patch("app.downloads.manager.os.path.exists", return_value=True)
    def test_move_completed_treats_non_update_metadata_as_generic_import(
        self,
        exists_mock,
        get_libraries_path_mock,
        move_generic_mock,
        select_candidate_mock,
    ):
        moved_path, reason = _move_completed_with_reason(
            {"path": "C:\\tests\\completed\\Example Title BASE"},
            {
                "title_id": "0100000000010000",
                "title_name": "Example Title",
                "app_type": "BASE",
                "version": 65536,
            },
        )

        self.assertEqual(moved_path, "X:\\library\\Example Title [BASE].nsp")
        self.assertIsNone(reason)
        move_generic_mock.assert_called_once_with("C:\\tests\\completed\\Example Title BASE", "X:\\library")
        select_candidate_mock.assert_not_called()

    @patch("app.downloads.manager._cleanup_download_path")
    @patch("app.downloads.manager.shutil.move")
    @patch("app.downloads.manager.os.makedirs")
    @patch("app.downloads.manager._ensure_unique_path", side_effect=lambda path: path)
    @patch("app.downloads.manager.get_libraries_path", return_value=["X:\\library"])
    @patch("app.downloads.manager.os.path.exists", return_value=True)
    @patch("app.downloads.manager._get_local_known_update_version", return_value=0)
    @patch("app.downloads.manager._get_highest_owned_update_version", return_value=655360)
    @patch("app.downloads.manager._select_completed_update_candidate", return_value=("C:\\tests\\completed\\sample_v983040.nsp.hdf", 983040))
    def test_move_completed_imports_newer_fallback_update_version(
        self,
        select_candidate_mock,
        highest_owned_mock,
        _get_local_known_update_version_mock,
        exists_mock,
        get_libraries_path_mock,
        ensure_unique_path_mock,
        makedirs_mock,
        move_mock,
        cleanup_mock,
    ):
        moved_path, reason = _move_completed_with_reason(
            {"path": "C:\\tests\\completed\\Sample Release"},
            {
                "title_id": "0100C62011050000",
                "app_id": "0100C62011050800",
                "title_name": "Sample Game",
                "version": 1376256,
            },
        )

        self.assertIsNone(reason)
        self.assertIn("Updates\\v983040", _normalize_fixture_path(moved_path))
        self.assertIn("Sample Game [0100C62011050800] [UPDATE][v983040].nsp", _normalize_fixture_path(moved_path))
        move_mock.assert_called_once_with(
            "C:\\tests\\completed\\sample_v983040.nsp.hdf",
            moved_path,
        )
        cleanup_mock.assert_called_once_with("C:\\tests\\completed\\Sample Release", "X:\\library")

    @patch("app.downloads.manager.shutil.move")
    @patch("app.downloads.manager.get_libraries_path", return_value=["X:\\library"])
    @patch("app.downloads.manager.os.path.exists", return_value=True)
    @patch("app.downloads.manager._get_local_known_update_version", return_value=0)
    @patch("app.downloads.manager._get_highest_owned_update_version", return_value=1376256)
    @patch("app.downloads.manager._select_completed_update_candidate", return_value=("C:\\tests\\completed\\sample_v983040.nsp.hdf", 983040))
    def test_move_completed_rejects_non_newer_update_version(
        self,
        select_candidate_mock,
        highest_owned_mock,
        _get_local_known_update_version_mock,
        exists_mock,
        get_libraries_path_mock,
        move_mock,
    ):
        moved_path, reason = _move_completed_with_reason(
            {"path": "C:\\tests\\completed\\Sample Release"},
            {
                "title_id": "0100C62011050000",
                "title_name": "Sample Game",
                "version": 1376256,
            },
        )

        self.assertIsNone(moved_path)
        self.assertEqual(reason, "duplicate update: downloaded v983040 is not newer than known v1376256")
        move_mock.assert_not_called()

    @patch("app.downloads.manager._cleanup_download_path")
    @patch("app.downloads.manager._normalize_imported_wrapped_files", side_effect=lambda path: path[:-4] if path.endswith(".hdf") else path)
    @patch("app.downloads.manager._build_generic_import_destination", side_effect=lambda dest_root, src_path: ntpath.join(dest_root, ntpath.basename(src_path)))
    @patch("app.downloads.manager.shutil.move")
    @patch(
        "app.downloads.manager._iter_importable_download_files",
        return_value=[
            "C:\\tests\\completed\\sample_v983040.nsp.hdf",
            "C:\\tests\\completed\\sample-dlc.nsp.hdf",
        ],
    )
    @patch("app.downloads.manager.get_libraries_path", return_value=["X:\\library"])
    @patch("app.downloads.manager.os.path.exists", return_value=True)
    @patch("app.downloads.manager._get_local_known_update_version", return_value=0)
    @patch("app.downloads.manager._get_highest_owned_update_version", return_value=1376256)
    @patch("app.downloads.manager._select_completed_update_candidate", return_value=("C:\\tests\\completed\\sample_v983040.nsp.hdf", 983040))
    def test_move_completed_imports_other_files_when_update_is_not_newer(
        self,
        select_candidate_mock,
        highest_owned_mock,
        _get_local_known_update_version_mock,
        exists_mock,
        get_libraries_path_mock,
        importable_files_mock,
        move_mock,
        build_dest_mock,
        normalize_mock,
        cleanup_mock,
    ):
        moved_path, reason = _move_completed_with_reason(
            {"path": "C:\\tests\\completed\\Sample Release"},
            {
                "title_id": "0100C62011050000",
                "title_name": "Sample Game",
                "version": 1376256,
            },
        )

        self.assertIsNone(reason)
        self.assertEqual(_normalize_fixture_path(moved_path), "X:\\library\\sample-dlc.nsp")
        move_mock.assert_called_once_with(
            "C:\\tests\\completed\\sample-dlc.nsp.hdf",
            "X:\\library\\sample-dlc.nsp.hdf",
        )
        cleanup_mock.assert_called_once_with("C:\\tests\\completed\\Sample Release", "X:\\library")

    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "0100C62011050000:1376256": {
                "title_id": "0100C62011050000",
                "version": 1376256,
                "hash": "nzo123",
                "id": "nzo123",
                "expected_name": "Sample Release",
                "title_name": "Sample Game",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": None,
            }
        },
        "completed": set(),
    })
    @patch("app.downloads.manager._move_completed_with_reason", return_value=(None, "downloaded v983040 is not newer than owned v1376256"))
    def test_check_completed_marks_item_stuck_when_import_is_not_newer(
        self,
        move_completed_mock,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
    ):
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd"})]
        list_completed_mock.return_value = [{
            "id": "nzo123",
            "hash": "nzo123",
            "name": "Sample Release",
            "path": "C:\\tests\\completed\\Sample Release",
        }]

        _check_completed({})

        pending_item = next(iter(downloads_manager._state["pending"].values()))
        self.assertEqual(pending_item["state"], "stuck")
        self.assertEqual(
            pending_item["state_reason"],
            "downloaded v983040 is not newer than owned v1376256",
        )

    @patch("app.downloads.manager._adopt_untracked_completed_item")
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "0100C62011050000:1376256": {
                "title_id": "0100C62011050000",
                "version": 1376256,
                "hash": "nzo123",
                "id": "nzo123",
                "expected_name": "Sample Release",
                "title_name": "Sample Game",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": None,
            }
        },
        "completed": set(),
    })
    @patch("app.downloads.manager._move_completed_with_reason", return_value=(None, "move failed"))
    def test_check_completed_does_not_re_adopt_failed_tracked_item_as_untracked(
        self,
        move_completed_mock,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
        adopt_untracked_mock,
    ):
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd"})]
        list_completed_mock.return_value = [{
            "id": "nzo123",
            "hash": "nzo123",
            "name": "Sample Release",
            "path": "C:\\tests\\completed\\Sample Release",
        }]

        _check_completed({})

        adopt_untracked_mock.assert_not_called()

    @patch("app.downloads.manager.remove_completed_download", return_value=(True, "ok"))
    @patch("app.downloads.manager.list_completed_downloads")
    @patch("app.downloads.manager._get_completed_poll_targets")
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "0100C62011050000:1376256": {
                "title_id": "0100C62011050000",
                "version": 1376256,
                "hash": "nzo123",
                "id": "nzo123",
                "expected_name": "Sample Release",
                "title_name": "Sample Game",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": None,
            }
        },
        "completed": set(),
        "completed_identities": set(),
        "duplicates": [],
    })
    @patch("app.downloads.manager._move_completed_with_reason", return_value=(None, "duplicate update: 0100C62011050000 v1376256 already known"))
    def test_check_completed_marks_duplicate_and_removes_pending_item(
        self,
        _move_completed_mock,
        _state_lock_mock,
        poll_targets_mock,
        list_completed_mock,
        remove_completed_mock,
    ):
        poll_targets_mock.return_value = [("usenet", {"type": "sabnzbd"})]
        list_completed_mock.return_value = [{
            "id": "nzo123",
            "hash": "nzo123",
            "name": "Sample Release",
            "path": "C:\\tests\\completed\\Sample Release",
            "protocol": "usenet",
            "client_type": "sabnzbd",
        }]

        _check_completed({})

        self.assertEqual(downloads_manager._state["pending"], {})
        self.assertIn("0100C62011050000:1376256", downloads_manager._state["completed"])
        self.assertEqual(len(downloads_manager._state.get("duplicates") or []), 1)
        self.assertIn("duplicate update", downloads_manager._state["duplicates"][0]["reason"])
        remove_completed_mock.assert_called_once()

    @patch("app.downloads.manager._delete_download_payload", return_value=(True, None))
    @patch("app.downloads.manager.remove_active_download", return_value=(True, "ok"))
    @patch("app.downloads.manager._get_download_activity_snapshot")
    @patch("app.downloads.manager._restore_pending_from_active")
    @patch("app.downloads.manager.load_settings", return_value={
        "downloads": {
            "usenet_client": {
                "type": "sabnzbd",
                "url": "http://sab.local",
                "api_key": "secret",
            }
        }
    })
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "manual:1": {
                "title_id": None,
                "version": None,
                "hash": "nzo123",
                "id": "nzo123",
                "expected_name": "Sample Release",
                "title_name": "Sample Release",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": "C:\\tests\\completed\\Sample Release",
            }
        },
        "completed": set(),
    })
    def test_remove_pending_download_cleans_up_active_item_and_payload(
        self,
        _state_lock_mock,
        load_settings_mock,
        restore_pending_mock,
        snapshot_mock,
        remove_active_mock,
        delete_payload_mock,
    ):
        snapshot_mock.return_value = {
            "active_by_protocol": {
                "usenet": {
                    "client_cfg": {"type": "sabnzbd", "url": "http://sab.local", "api_key": "secret"},
                    "items": [{
                        "id": "nzo123",
                        "hash": "nzo123",
                        "name": "Sample Release",
                        "path": "C:\\tests\\completed\\Sample Release",
                    }],
                }
            },
            "completed_by_protocol": {"usenet": {"client_cfg": {"type": "sabnzbd"}, "items": []}},
        }

        ok, message = remove_pending_download("manual:1")

        self.assertTrue(ok)
        self.assertEqual(message, "Removed queued download.")
        self.assertEqual(downloads_manager._state["pending"], {})
        remove_active_mock.assert_called_once()
        delete_payload_mock.assert_called_once_with("C:\\tests\\completed\\Sample Release")

    @patch("app.downloads.manager._delete_download_payload", return_value=(False, "access denied"))
    @patch("app.downloads.manager.remove_active_download", return_value=(True, "ok"))
    @patch("app.downloads.manager._get_download_activity_snapshot")
    @patch("app.downloads.manager._restore_pending_from_active")
    @patch("app.downloads.manager.load_settings", return_value={
        "downloads": {
            "usenet_client": {
                "type": "sabnzbd",
                "url": "http://sab.local",
                "api_key": "secret",
            }
        }
    })
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "manual:1": {
                "title_id": None,
                "version": None,
                "hash": "nzo123",
                "id": "nzo123",
                "expected_name": "Sample Release",
                "title_name": "Sample Release",
                "protocol": "usenet",
                "client_type": "sabnzbd",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": "C:\\tests\\completed\\Sample Release",
            }
        },
        "completed": set(),
    })
    def test_remove_pending_download_keeps_item_when_payload_cleanup_fails(
        self,
        _state_lock_mock,
        load_settings_mock,
        restore_pending_mock,
        snapshot_mock,
        remove_active_mock,
        delete_payload_mock,
    ):
        snapshot_mock.return_value = {
            "active_by_protocol": {
                "usenet": {
                    "client_cfg": {"type": "sabnzbd", "url": "http://sab.local", "api_key": "secret"},
                    "items": [{
                        "id": "nzo123",
                        "hash": "nzo123",
                        "name": "Sample Release",
                        "path": "C:\\tests\\completed\\Sample Release",
                    }],
                }
            },
            "completed_by_protocol": {"usenet": {"client_cfg": {"type": "sabnzbd"}, "items": []}},
        }

        ok, message = remove_pending_download("manual:1")

        self.assertFalse(ok)
        self.assertIn("access denied", message)
        self.assertEqual(downloads_manager._state["pending"]["manual:1"]["state"], "stuck")
        self.assertEqual(downloads_manager._state["pending"]["manual:1"]["state_reason"], "delete failed: access denied")

    @patch("app.downloads.manager._get_download_activity_snapshot")
    @patch("app.downloads.manager._restore_pending_from_active")
    @patch("app.downloads.manager.load_settings", return_value={"downloads": {}})
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "manual:1773523046": {
                "title_id": None,
                "version": None,
                "hash": "abc123",
                "id": "abc123",
                "expected_name": "Game",
                "title_name": "Game",
                "protocol": "torrent",
                "client_type": "qbittorrent",
                "state": "stuck",
                "state_reason": "delete failed: download client is not configured",
                "last_seen_status": "stuck",
                "last_seen_path": None,
            }
        },
        "completed": set(),
    })
    def test_remove_pending_download_removes_stale_local_entry_without_live_match(
        self,
        _state_lock_mock,
        load_settings_mock,
        restore_pending_mock,
        snapshot_mock,
    ):
        snapshot_mock.return_value = {
            "active_by_protocol": {},
            "completed_by_protocol": {},
        }

        ok, message = remove_pending_download("manual:1773523046")

        self.assertTrue(ok)
        self.assertEqual(message, "Removed stale queue entry.")
        self.assertEqual(downloads_manager._state["pending"], {})

    @patch("app.downloads.manager._delete_download_payload")
    @patch("app.downloads.manager._get_download_activity_snapshot")
    @patch("app.downloads.manager._restore_pending_from_active")
    @patch("app.downloads.manager.load_settings", return_value={
        "downloads": {
            "torrent_client": {
                "type": "qbittorrent",
                "url": "http://torrent.local",
            }
        }
    })
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {
            "manual:2": {
                "title_id": None,
                "version": None,
                "hash": "abc123",
                "id": "abc123",
                "expected_name": "Game",
                "title_name": "Game",
                "protocol": "torrent",
                "client_type": "qbittorrent",
                "state": "queued",
                "state_reason": None,
                "last_seen_status": None,
                "last_seen_path": "C:\\tests\\completed\\Game",
            }
        },
        "completed": set(),
    })
    def test_remove_pending_download_keeps_item_when_snapshot_has_errors(
        self,
        _state_lock_mock,
        load_settings_mock,
        restore_pending_mock,
        snapshot_mock,
        delete_payload_mock,
    ):
        snapshot_mock.return_value = {
            "active_by_protocol": {"torrent": {"client_cfg": {"type": "qbittorrent"}, "items": []}},
            "completed_by_protocol": {"torrent": {"client_cfg": {"type": "qbittorrent"}, "items": []}},
            "errors_by_protocol": {"torrent": ["active: timeout"]},
        }

        ok, message = remove_pending_download("manual:2")

        self.assertFalse(ok)
        self.assertEqual(
            message,
            "Failed to remove queued download: could not verify downloader state",
        )
        self.assertEqual(downloads_manager._state["pending"]["manual:2"]["state"], "stuck")
        self.assertEqual(
            downloads_manager._state["pending"]["manual:2"]["state_reason"],
            "delete failed: could not verify downloader state",
        )
        delete_payload_mock.assert_not_called()

    @patch("app.downloads.manager._delete_download_payload", return_value=(True, None))
    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {},
        "completed": set(),
        "duplicates": [{
            "id": "dup-1",
            "label": "Example Release NSW-GRP",
            "path": "X:\\fixture-root\\downloads\\Example Release",
            "reason": "duplicate basegame: 0100EXAMPLE000000 already exists in library",
        }],
    })
    def test_remove_duplicate_download_deletes_file_and_removes_entry(
        self,
        _state_lock_mock,
        delete_payload_mock,
    ):
        ok, message = remove_duplicate_download("dup-1")

        self.assertTrue(ok)
        self.assertEqual(message, "Deleted rejected duplicate file.")
        self.assertEqual(downloads_manager._state.get("duplicates"), [])
        delete_payload_mock.assert_called_once_with("X:\\fixture-root\\downloads\\Example Release")

    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {},
        "completed": set(),
        "duplicates": [{
            "id": "dup-2",
            "label": "Example Release NSW-GRP",
            "path": None,
            "reason": "duplicate update: 0100EXAMPLE000000 v65536 already known",
        }],
    })
    def test_remove_duplicate_download_rejects_when_path_missing(
        self,
        _state_lock_mock,
    ):
        ok, message = remove_duplicate_download("dup-2")

        self.assertFalse(ok)
        self.assertEqual(message, "Duplicate entry has no deletable path.")
        self.assertEqual(len(downloads_manager._state.get("duplicates") or []), 1)

    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {},
        "completed": set(),
        "duplicates": [{
            "id": "dup-3",
            "label": "Example Release NSW-GRP",
            "path": None,
            "reason": "duplicate update: 0100EXAMPLE000000 v65536 already known",
        }],
    })
    def test_dismiss_duplicate_download_removes_entry_without_path(
        self,
        _state_lock_mock,
    ):
        ok, message = dismiss_duplicate_download("dup-3")

        self.assertTrue(ok)
        self.assertEqual(message, "Removed duplicate entry.")
        self.assertEqual(downloads_manager._state.get("duplicates"), [])

    @patch("app.downloads.manager._state_lock")
    @patch("app.downloads.manager._state", {
        "running": False,
        "last_run": 0.0,
        "pending": {},
        "completed": set(),
        "duplicates": [{
            "id": None,
            "timestamp": 1234567890,
            "label": "Legacy Entry",
            "reason": "duplicate basegame: already exists",
            "protocol": "torrent",
            "path": None,
        }],
    })
    def test_dismiss_duplicate_download_removes_legacy_entry_by_fingerprint(
        self,
        _state_lock_mock,
    ):
        ok, message = dismiss_duplicate_download(
            "",
            fingerprint={
                "timestamp": 1234567890,
                "label": "Legacy Entry",
                "reason": "duplicate basegame: already exists",
                "protocol": "torrent",
            },
        )

        self.assertTrue(ok)
        self.assertEqual(message, "Removed duplicate entry.")
        self.assertEqual(downloads_manager._state.get("duplicates"), [])

class PendingQueueReconciliationTests(unittest.TestCase):
    def test_restored_sab_job_blocks_automatic_search_for_same_update(self):
        state = {
            "running": False,
            "last_run": 0.0,
            "pending": {
                "restored:usenet:sabnzbd:nzo123": {
                    "title_id": None,
                    "version": None,
                    "expected_name": "Example Title Update [v196608] NSW-GRP",
                    "title_name": "Example Title Update [v196608] NSW-GRP",
                    "protocol": "usenet",
                    "client_type": "sabnzbd",
                },
            },
            "completed": set(),
            "completed_identities": set(),
            "duplicates": [],
        }
        with patch("app.downloads.manager._state", state):
            self.assertTrue(downloads_manager._already_tracked(
                "0100EXAMPLE000000:196608",
                update={
                    "title_id": "0100EXAMPLE000000",
                    "title_name": "Example Title",
                    "version": 196608,
                },
            ))

    @patch("app.downloads.manager._persist_downloads_state_locked")
    @patch("app.downloads.manager._is_protocol_client_configured", return_value=True)
    @patch("app.downloads.manager.time.time", return_value=200.0)
    def test_reconcile_removes_job_absent_from_sab_after_grace_period(
        self,
        time_mock,
        configured_mock,
        persist_mock,
    ):
        state = {
            "running": False,
            "last_run": 0.0,
            "pending": {
                "0100EXAMPLE000000:196608": {
                    "title_id": "0100EXAMPLE000000",
                    "version": 196608,
                    "id": "nzo123",
                    "hash": "nzo123",
                    "protocol": "usenet",
                    "client_type": "sabnzbd",
                    "missing_since": 100.0,
                },
            },
            "completed": set(),
            "completed_identities": set(),
            "duplicates": [],
        }
        snapshot = {
            "active_by_protocol": {"usenet": {"items": []}},
            "completed_by_protocol": {"usenet": {"items": []}},
            "errors_by_protocol": {},
        }
        with patch("app.downloads.manager._state", state):
            removed = downloads_manager._reconcile_missing_pending_downloads({}, snapshot)

        self.assertEqual(removed, 1)
        self.assertEqual(state["pending"], {})
        configured_mock.assert_called_once_with({}, "usenet")
        persist_mock.assert_called_once()

    @patch("app.downloads.manager._persist_downloads_state_locked")
    @patch("app.downloads.manager._is_protocol_client_configured", return_value=True)
    @patch("app.downloads.manager.time.time", return_value=200.0)
    def test_reconcile_keeps_job_when_sab_poll_failed(
        self,
        time_mock,
        configured_mock,
        persist_mock,
    ):
        state = {
            "running": False,
            "last_run": 0.0,
            "pending": {
                "0100EXAMPLE000000:196608": {
                    "id": "nzo123",
                    "hash": "nzo123",
                    "protocol": "usenet",
                    "missing_since": 100.0,
                },
            },
            "completed": set(),
            "completed_identities": set(),
            "duplicates": [],
        }
        snapshot = {
            "active_by_protocol": {"usenet": {"items": []}},
            "completed_by_protocol": {"usenet": {"items": []}},
            "errors_by_protocol": {"usenet": ["active: unavailable"]},
        }
        with patch("app.downloads.manager._state", state):
            removed = downloads_manager._reconcile_missing_pending_downloads({}, snapshot)

        self.assertEqual(removed, 0)
        self.assertIn("0100EXAMPLE000000:196608", state["pending"])
        configured_mock.assert_not_called()
        persist_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
