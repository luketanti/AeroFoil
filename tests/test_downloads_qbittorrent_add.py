import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


_MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "downloads" / "torrent_client.py"
_SPEC = importlib.util.spec_from_file_location("torrent_client_module", _MODULE_PATH)
torrent_client = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(torrent_client)


class _FakeResponse:
    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self.text = text
        self._json_data = json_data

    def json(self):
        return self._json_data


class _FakeSession:
    def __init__(self, add_text="Ok.", info_by_hash=None, managed_items=None):
        self.headers = {}
        self._add_text = add_text
        self._info_by_hash = dict(info_by_hash or {})
        self._managed_items = list(managed_items or [])

    def post(self, url, data=None, timeout=None):
        if url.endswith("/api/v2/auth/login"):
            return _FakeResponse(status_code=200, text="Ok.")
        if url.endswith("/api/v2/torrents/add"):
            return _FakeResponse(status_code=200, text=self._add_text)
        if url.endswith("/api/v2/torrents/removeTags"):
            return _FakeResponse(status_code=200, text="")
        if url.endswith("/api/v2/torrents/resume"):
            return _FakeResponse(status_code=200, text="")
        if url.endswith("/api/v2/torrents/filePrio"):
            return _FakeResponse(status_code=200, text="")
        if url.endswith("/api/v2/torrents/delete"):
            return _FakeResponse(status_code=200, text="")
        return _FakeResponse(status_code=404, text="")

    def get(self, url, params=None, timeout=None):
        if url.endswith("/api/v2/torrents/info"):
            if params and params.get("hashes"):
                lookup = str(params.get("hashes") or "").lower()
                item = self._info_by_hash.get(lookup)
                if item:
                    return _FakeResponse(status_code=200, json_data=[item])
                return _FakeResponse(status_code=200, json_data=[])
            return _FakeResponse(status_code=200, json_data=list(self._managed_items))
        if url.endswith("/api/v2/torrents/files"):
            return _FakeResponse(status_code=200, json_data=[])
        return _FakeResponse(status_code=404, json_data=[])


class QBittorrentAddTests(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://qbittorrent.local"
        self.magnet_hash = "3b245504cf5f11bbdbb2e120e036ff83aeb8c145"
        self.magnet_url = f"magnet:?xt=urn:btih:{self.magnet_hash}&dn=test"

    def test_add_rejects_when_qbittorrent_does_not_create_torrent(self):
        fake_session = _FakeSession(add_text="Ok.", info_by_hash={}, managed_items=[])
        with patch.object(torrent_client.requests, "Session", return_value=fake_session), patch.object(
            torrent_client.time, "sleep", lambda _seconds: None
        ):
            ok, message, torrent_hash = torrent_client._add_qbittorrent(
                url=self.base_url,
                username="admin",
                password="admin",
                download_url=self.magnet_url,
                category="aerofoil",
                download_path="",
                timeout_seconds=1,
                expected_name="Test Title",
                update_only=False,
                exclude_russian=False,
                expected_update_number=None,
                expected_version=None,
            )

        self.assertFalse(ok)
        self.assertIn("did not report", message.lower())
        self.assertIsNone(torrent_hash)

    def test_add_succeeds_when_hash_is_resolved_in_qbittorrent(self):
        fake_session = _FakeSession(
            add_text="Ok.",
            info_by_hash={
                self.magnet_hash: {
                    "hash": self.magnet_hash,
                    "name": "Test Title",
                    "tags": "aerofoil",
                    "added_on": 123,
                }
            },
            managed_items=[],
        )
        with patch.object(torrent_client.requests, "Session", return_value=fake_session), patch.object(
            torrent_client.time, "sleep", lambda _seconds: None
        ):
            ok, message, torrent_hash = torrent_client._add_qbittorrent(
                url=self.base_url,
                username="admin",
                password="admin",
                download_url=self.magnet_url,
                category="aerofoil",
                download_path="",
                timeout_seconds=1,
                expected_name="Test Title",
                update_only=False,
                exclude_russian=False,
                expected_update_number=None,
                expected_version=None,
            )

        self.assertTrue(ok)
        self.assertIn("accepted", message.lower())
        self.assertEqual(torrent_hash, self.magnet_hash)

    def test_add_rejects_non_ok_response_body(self):
        fake_session = _FakeSession(add_text="Fails.", info_by_hash={}, managed_items=[])
        with patch.object(torrent_client.requests, "Session", return_value=fake_session), patch.object(
            torrent_client.time, "sleep", lambda _seconds: None
        ):
            ok, message, torrent_hash = torrent_client._add_qbittorrent(
                url=self.base_url,
                username="admin",
                password="admin",
                download_url=self.magnet_url,
                category="aerofoil",
                download_path="",
                timeout_seconds=1,
                expected_name="Test Title",
                update_only=False,
                exclude_russian=False,
                expected_update_number=None,
                expected_version=None,
            )

        self.assertFalse(ok)
        self.assertIn("rejected", message.lower())
        self.assertIsNone(torrent_hash)


if __name__ == "__main__":
    unittest.main()
