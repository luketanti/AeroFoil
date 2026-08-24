import unittest
from unittest.mock import patch

from app.downloads.manager import _extract_update_version_from_name, _get_import_extension, _infer_protocol
from app.downloads.prowlarr import ProwlarrClient, _normalize_result, filter_results, pick_best_result
from app.downloads.versioning import select_dlc_file_indices, select_update_file_indices
from app.settings import _normalize_download_settings


class DownloadProtocolTests(unittest.TestCase):
    def test_normalize_result_preserves_usenet_protocol(self):
        item = {
            "title": "Game Update NZB",
            "downloadUrl": "https://example.test/file.nzb",
            "protocol": "usenet",
        }
        normalized = _normalize_result(item)
        self.assertEqual(normalized["protocol"], "usenet")

    def test_normalize_result_infers_torrent_from_magnet(self):
        item = {
            "title": "Game Update Torrent",
            "downloadUrl": "magnet:?xt=urn:btih:abc123",
        }
        normalized = _normalize_result(item)
        self.assertEqual(normalized["protocol"], "torrent")

    def test_normalize_result_preserves_indexer_name(self):
        item = {
            "title": "Game Update NZB",
            "downloadUrl": "https://example.test/file.nzb",
            "indexer": "Indexer One",
        }
        normalized = _normalize_result(item)
        self.assertEqual(normalized["indexer"], "Indexer One")

    def test_pick_best_result_filters_to_configured_protocols(self):
        results = [
            {"title": "Game Update", "seeders": 50, "size": 1, "protocol": "torrent"},
            {"title": "Game Update", "seeders": 0, "size": 2, "protocol": "usenet"},
        ]
        best = pick_best_result(results, allowed_protocols=["usenet"])
        self.assertEqual(best["protocol"], "usenet")

    def test_pick_best_result_requires_exact_version_for_usenet_when_enabled(self):
        results = [
            {"title": "Sample Package Update v1.25.0 TEST-GRP", "seeders": 0, "size": 2, "protocol": "usenet"},
            {"title": "Sample Package Update [v1245184]", "seeders": 0, "size": 1, "protocol": "usenet"},
        ]
        best = pick_best_result(results, allowed_protocols=["usenet"], version=1245184, require_exact_version=True)
        self.assertEqual(best["title"], "Sample Package Update [v1245184]")

    def test_pick_best_result_requires_exact_version_for_torrent_when_enabled(self):
        results = [
            {"title": "Game Update v1.25.0 Torrent", "seeders": 50, "size": 2, "protocol": "torrent"},
            {"title": "Game Update [v1245184] Torrent", "seeders": 10, "size": 1, "protocol": "torrent"},
        ]
        best = pick_best_result(results, allowed_protocols=["torrent"], version=1245184, require_exact_version=True)
        self.assertEqual(best["title"], "Game Update [v1245184] Torrent")

    def test_resolve_protocol_infers_nzb(self):
        self.assertEqual(_infer_protocol("https://example.test/update.nzb"), "usenet")

    def test_download_settings_include_legacy_and_usenet_clients(self):
        normalized = _normalize_download_settings({
            "category": "shared-tag",
            "min_seeders": 7,
            "torrent_client": {"url": "http://torrent.local:8080"},
        })
        self.assertEqual(normalized["torrent_client"]["type"], "qbittorrent")
        self.assertEqual(normalized["usenet_client"]["type"], "sabnzbd")
        self.assertEqual(normalized["category"], "shared-tag")
        self.assertEqual(normalized["torrent_client"]["category"], "shared-tag")
        self.assertEqual(normalized["usenet_client"]["category"], "shared-tag")
        self.assertEqual(normalized["torrent_client"]["min_seeders"], 7)
        self.assertTrue(normalized["torrent_client"]["remove_completed_torrents_on_finish"])
        self.assertFalse(normalized["torrent_client"]["use_hardlinks_when_seeding"])
        self.assertEqual(normalized["usenet_client"]["min_age_minutes"], 0)
        self.assertEqual(normalized["prowlarr"]["search_limit"], 100)
        self.assertEqual(normalized["required_terms_match"], "all")

    def test_download_settings_reject_invalid_required_terms_match_mode(self):
        normalized = _normalize_download_settings({"required_terms_match": "unsupported"})

        self.assertEqual(normalized["required_terms_match"], "all")

    def test_download_settings_allow_disabling_torrent_cleanup(self):
        normalized = _normalize_download_settings({
            "torrent_client": {
                "remove_completed_torrents_on_finish": False,
            },
        })
        self.assertFalse(normalized["torrent_client"]["remove_completed_torrents_on_finish"])

    def test_download_settings_allow_hardlinks_when_seeding(self):
        normalized = _normalize_download_settings({
            "torrent_client": {
                "use_hardlinks_when_seeding": True,
            },
        })

        self.assertTrue(normalized["torrent_client"]["use_hardlinks_when_seeding"])

    @patch.object(ProwlarrClient, "_get")
    def test_prowlarr_search_sends_type_and_nonzero_limit(self, get_mock):
        get_mock.return_value = []
        client = ProwlarrClient("http://prowlarr.local", "secret")

        client.search("Sample update", indexer_ids=[2], categories=[1000], limit=None)

        self.assertEqual(get_mock.call_args.args[0], "/api/v1/search")
        params = get_mock.call_args.kwargs["params"]
        self.assertEqual(params["query"], "Sample update")
        self.assertEqual(params["type"], "search")
        self.assertEqual(params["limit"], 100)
        self.assertEqual(params["indexerIds"], [2])
        self.assertEqual(params["categories"], [1000])

    def test_normalize_result_extracts_age_from_publish_date(self):
        normalized = _normalize_result({
            "title": "Game Update NZB",
            "downloadUrl": "https://example.test/file.nzb",
            "publishDate": "2026-03-14T14:00:00Z",
        })
        self.assertIsInstance(normalized["age_minutes"], int)
        self.assertGreaterEqual(normalized["age_minutes"], 0)
        self.assertTrue(normalized["age_label"])
        self.assertEqual(normalized["published_at"], "2026-03-14T14:00:00Z")

    def test_filter_results_applies_usenet_min_age(self):
        results = [
            {"title": "Fresh NZB", "protocol": "usenet", "age_minutes": 30},
            {"title": "Older NZB", "protocol": "usenet", "age_minutes": 120},
            {"title": "Torrent", "protocol": "torrent", "seeders": 10},
        ]
        filtered = filter_results(results, min_seeders=0, min_age_minutes=60)
        self.assertEqual([item["title"] for item in filtered], ["Older NZB", "Torrent"])

    def test_filter_results_applies_blacklist_terms(self):
        results = [
            {"title": "Sample Base Game", "protocol": "torrent", "seeders": 10},
            {"title": "Sample Base Game Update", "protocol": "torrent", "seeders": 10},
        ]
        filtered = filter_results(results, blacklist_terms=["update"])
        self.assertEqual([item["title"] for item in filtered], ["Sample Base Game"])

    def test_filter_results_matches_any_required_term_when_configured(self):
        results = [
            {"title": "Example alpha release", "protocol": "torrent", "seeders": 10},
            {"title": "Example beta release", "protocol": "torrent", "seeders": 10},
            {"title": "Example other release", "protocol": "torrent", "seeders": 10},
        ]

        filtered = filter_results(results, required_terms=["alpha", "beta"], required_terms_match="any")

        self.assertEqual([item["title"] for item in filtered], ["Example alpha release", "Example beta release"])

    def test_filter_results_requires_all_terms_by_default(self):
        results = [
            {"title": "Example alpha release", "protocol": "torrent", "seeders": 10},
            {"title": "Example alpha beta release", "protocol": "torrent", "seeders": 10},
        ]

        filtered = filter_results(results, required_terms=["alpha", "beta"])

        self.assertEqual([item["title"] for item in filtered], ["Example alpha beta release"])

    def test_select_dlc_file_indices_prefers_dlc_named_files(self):
        file_names = [
            "Example Game [0100AAAA00000000] [BASE].nsp",
            "Example Game [0100AAAA00000001] [DLC][v0].nsp",
            "Example Game bonus.dat",
        ]

        self.assertEqual(select_dlc_file_indices(file_names), [1])

    def test_select_dlc_file_indices_matches_dlc_app_id_suffix(self):
        file_names = [
            "0100AAAA00000000.nsp",
            "0100AAAA00000001.nsp",
        ]

        self.assertEqual(select_dlc_file_indices(file_names), [1])

    def test_select_update_file_indices_ignores_base_app_id_with_zero_version(self):
        file_names = [
            "Generic Base Game [010096500EA94000][v0].nsp",
        ]

        self.assertEqual(select_update_file_indices(file_names), [])

    def test_select_update_file_indices_prefers_real_update_over_base_file(self):
        file_names = [
            "Generic Base Game [010096500EA94000][v0].nsp",
            "Generic Update [010096500EA94800][v65536].nsp",
        ]

        self.assertEqual(select_update_file_indices(file_names), [1])

    def test_select_update_file_indices_rejects_torrent_without_requested_version(self):
        file_names = [
            "Example Title Update [0100DAA012C1A800][v4054232].nsp",
        ]

        self.assertEqual(select_update_file_indices(file_names, expected_version=4128768), [])

    def test_extract_update_version_prefers_bracketed_token(self):
        self.assertEqual(_extract_update_version_from_name("Game [v1245184] v999.nsp"), 1245184)

    def test_extract_update_version_falls_back_to_plain_token(self):
        self.assertEqual(_extract_update_version_from_name("sample_v1245184.nsp.hdf"), 1245184)

    def test_extract_update_version_ignores_semantic_version(self):
        self.assertIsNone(_extract_update_version_from_name("Sample Update v1.1.10 TEST-GRP"))

    def test_get_import_extension_strips_hdf_wrapper(self):
        self.assertEqual(_get_import_extension("C:\\tests\\completed\\sample_v1245184.nsp.hdf"), "nsp")


if __name__ == "__main__":
    unittest.main()
