import unittest
from unittest.mock import patch

from app.downloads import torrent_client


class RTorrentClientTests(unittest.TestCase):
    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    def test_test_rtorrent_client_success(self, rpc_mock):
        rpc_mock.return_value = (True, None, "0.9.8")

        ok, message = torrent_client.test_torrent_client("rtorrent", "http://rtorrent.local")

        self.assertTrue(ok)
        self.assertIn("rTorrent OK", message)

    @patch("app.downloads.torrent_client._select_rtorrent_highest_version", return_value=True)
    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    @patch("app.downloads.torrent_client._get_torrent_file_list")
    def test_add_rtorrent_supports_update_only_selection(self, preflight_mock, rpc_mock, select_mock):
        preflight_mock.return_value = ["Example Update [v65536].nsp"]
        rpc_mock.return_value = (True, None, 0)

        ok, message, item_id = torrent_client.add_torrent(
            "rtorrent",
            "http://rtorrent.local",
            download_url="magnet:?xt=urn:btih:abcdef",
            update_only=True,
            expected_version=65536,
        )

        self.assertTrue(ok)
        self.assertEqual(message, "rTorrent accepted torrent.")
        self.assertEqual(item_id, "abcdef")
        select_mock.assert_called_once()
        load_call = next(call for call in rpc_mock.call_args_list if call.args[1] == "load.start_verbose")
        self.assertIn("d.custom1.set=aerofoil", load_call.args[2])

    @patch("app.downloads.torrent_client._set_rtorrent_file_priority")
    @patch("app.downloads.torrent_client.time.sleep", return_value=None)
    @patch("app.downloads.torrent_client._fetch_rtorrent_file_names")
    def test_select_rtorrent_highest_version_waits_for_file_names(self, fetch_names_mock, sleep_mock, priority_mock):
        fetch_names_mock.side_effect = [
            [],
            ["Example Update [v65536].nsp", "bonus.dat"],
        ]

        ok = torrent_client._select_rtorrent_highest_version(
            "http://rtorrent.local",
            "abcdef",
            "user",
            "pass",
            10,
            exclude_russian=False,
            expected_version=65536,
        )

        self.assertTrue(ok)
        self.assertEqual(fetch_names_mock.call_count, 2)
        self.assertTrue(sleep_mock.called)
        priority_mock.assert_any_call("http://rtorrent.local", "abcdef", 0, 0, "user", "pass", 10)
        priority_mock.assert_any_call("http://rtorrent.local", "abcdef", 1, 0, "user", "pass", 10)
        priority_mock.assert_any_call("http://rtorrent.local", "abcdef", 0, 1, "user", "pass", 10)

    @patch("app.downloads.torrent_client._compute_torrent_infohash", return_value=None)
    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    def test_add_rtorrent_resolves_hash_by_name_when_infohash_unavailable(self, rpc_mock, _infohash_mock):
        def fake_rpc(url, method, params=None, timeout_seconds=10, username=None, password=None, **kwargs):
            if method == "load.start_verbose":
                return True, None, 0
            if method == "download_list":
                return True, None, ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            if method == "d.name":
                return True, None, "Example Release NSW-GRP"
            if method == "d.custom1.set":
                return True, None, 0
            if method == "d.directory.set":
                return True, None, 0
            return True, None, 0

        rpc_mock.side_effect = fake_rpc

        ok, message, item_id = torrent_client.add_torrent(
            "rtorrent",
            "http://rtorrent.local",
            download_url="http://indexer.local/example.torrent",
            expected_name="Example Release NSW-GRP",
        )

        self.assertTrue(ok)
        self.assertEqual(message, "rTorrent accepted torrent.")
        self.assertEqual(item_id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        called_methods = [call.args[1] for call in rpc_mock.call_args_list]
        self.assertIn("d.custom1.set", called_methods)
        load_call = next(call for call in rpc_mock.call_args_list if call.args[1] == "load.start_verbose")
        self.assertIn("d.custom1.set=aerofoil", load_call.args[2])

    @patch("app.downloads.torrent_client._remove_rtorrent")
    @patch("app.downloads.torrent_client._select_rtorrent_highest_version", return_value=False)
    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    @patch("app.downloads.torrent_client._get_torrent_file_list")
    def test_add_rtorrent_update_only_cleans_up_when_no_matching_files(
        self,
        preflight_mock,
        rpc_mock,
        _select_mock,
        remove_mock,
    ):
        preflight_mock.return_value = ["Example Update [v65536].nsp"]
        rpc_mock.return_value = (True, None, 0)
        remove_mock.return_value = (True, "rTorrent removed torrent.")

        ok, message, item_id = torrent_client.add_torrent(
            "rtorrent",
            "http://rtorrent.local",
            download_url="magnet:?xt=urn:btih:abcdef",
            update_only=True,
            expected_version=65536,
        )

        self.assertFalse(ok)
        self.assertEqual(message, torrent_client.TORRENT_UPDATE_SELECTION_ERROR)
        self.assertIsNone(item_id)
        remove_mock.assert_called_once()

    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    def test_list_active_rtorrent_returns_only_managed_incomplete(self, rpc_mock):
        def fake_rpc(url, method, params=None, timeout_seconds=10, username=None, password=None, **kwargs):
            torrent_hash = (params or [None])[0]
            if method == "download_list":
                return True, None, ["hashA", "hashB"]
            if method == "d.custom1":
                return True, None, "aerofoil:games" if torrent_hash == "hashA" else "other"
            if method == "d.name":
                return True, None, "Example Release" if torrent_hash == "hashA" else "Other"
            if method == "d.directory":
                return True, None, "X:/fixture-root/downloads"
            if method == "d.complete":
                return True, None, 0
            if method == "d.bytes_done":
                return True, None, 512
            if method == "d.size_bytes":
                return True, None, 1024
            if method == "d.down.rate":
                return True, None, 100
            if method == "d.up.rate":
                return True, None, 10
            if method == "d.peers_connected":
                return True, None, 3
            return False, "unexpected", None

        rpc_mock.side_effect = fake_rpc

        items = torrent_client.list_active(
            "rtorrent",
            "http://rtorrent.local",
            category="games",
            download_path="X:/fixture-root",
        )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["hash"], "hashA")
        self.assertAlmostEqual(items[0]["progress"], 50.0)

    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    def test_list_completed_rtorrent_returns_only_managed_complete(self, rpc_mock):
        def fake_rpc(url, method, params=None, timeout_seconds=10, username=None, password=None, **kwargs):
            torrent_hash = (params or [None])[0]
            if method == "download_list":
                return True, None, ["hashA", "hashB"]
            if method == "d.custom1":
                return True, None, "aerofoil:games"
            if method == "d.name":
                return True, None, "Example Release" if torrent_hash == "hashA" else "Example Incomplete"
            if method == "d.directory":
                return True, None, "X:/fixture-root/downloads"
            if method == "d.complete":
                return True, None, 1 if torrent_hash == "hashA" else 0
            return False, "unexpected", None

        rpc_mock.side_effect = fake_rpc

        items = torrent_client.list_completed(
            "rtorrent",
            "http://rtorrent.local",
            category="games",
            download_path="X:/fixture-root",
        )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["hash"], "hashA")

    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    def test_list_completed_rtorrent_keeps_generic_managed_label_when_category_changed(self, rpc_mock):
        def fake_rpc(url, method, params=None, timeout_seconds=10, username=None, password=None, **kwargs):
            torrent_hash = (params or [None])[0]
            if method == "download_list":
                return True, None, ["hashA"]
            if method == "d.custom1":
                return True, None, "aerofoil"
            if method == "d.name":
                return True, None, "Example Release"
            if method == "d.directory":
                return True, None, "X:/fixture-root/downloads"
            if method == "d.complete":
                return True, None, 1 if torrent_hash == "hashA" else 0
            return False, "unexpected", None

        rpc_mock.side_effect = fake_rpc

        items = torrent_client.list_completed(
            "rtorrent",
            "http://rtorrent.local",
            category="games",
            download_path="X:/fixture-root",
        )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["hash"], "hashA")

    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    def test_list_completed_rtorrent_prefers_base_path_over_directory_plus_name(self, rpc_mock):
        def fake_rpc(url, method, params=None, timeout_seconds=10, username=None, password=None, **kwargs):
            torrent_hash = (params or [None])[0]
            if method == "download_list":
                return True, None, ["hashA"]
            if method == "d.custom1":
                return True, None, "aerofoil:games"
            if method == "d.name":
                return True, None, "title"
            if method == "d.directory":
                return True, None, "/downloads/complete/aerofoil:aerofoil/title"
            if method == "d.base_path":
                return True, None, "/downloads/complete/aerofoil:aerofoil/title"
            if method == "d.complete":
                return True, None, 1 if torrent_hash == "hashA" else 0
            return False, "unexpected", None

        rpc_mock.side_effect = fake_rpc

        items = torrent_client.list_completed(
            "rtorrent",
            "http://rtorrent.local",
            category="games",
            download_path="/downloads/complete",
        )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["hash"], "hashA")
        self.assertEqual(items[0]["path"], "/downloads/complete/aerofoil:aerofoil/title")

    @patch("app.downloads.torrent_client._rtorrent_xmlrpc")
    def test_remove_rtorrent_uses_erase_when_delete_files_true(self, rpc_mock):
        rpc_mock.return_value = (True, None, 0)

        ok, message = torrent_client.remove_torrent(
            "rtorrent",
            "http://rtorrent.local",
            "ABC123",
            delete_files=True,
        )

        self.assertTrue(ok)
        self.assertEqual(message, "rTorrent removed torrent.")
        self.assertEqual(rpc_mock.call_args_list[1].args[1], "d.erase")
        self.assertEqual(rpc_mock.call_args_list[0].args[2][0], "abc123")
        self.assertEqual(rpc_mock.call_args_list[1].args[2][0], "abc123")


if __name__ == "__main__":
    unittest.main()

