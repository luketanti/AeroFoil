import unittest
from unittest.mock import patch

from app.downloads import manager


class DownloadsManagerTests(unittest.TestCase):
    def setUp(self):
        self._original_state = {
            "running": manager._state["running"],
            "last_run": manager._state["last_run"],
            "pending": dict(manager._state["pending"]),
            "completed": set(manager._state["completed"]),
        }
        manager._state["running"] = False
        manager._state["last_run"] = 0.0
        manager._state["pending"].clear()
        manager._state["completed"].clear()

    def tearDown(self):
        manager._state["running"] = self._original_state["running"]
        manager._state["last_run"] = self._original_state["last_run"]
        manager._state["pending"].clear()
        manager._state["pending"].update(self._original_state["pending"])
        manager._state["completed"].clear()
        manager._state["completed"].update(self._original_state["completed"])

    def test_track_pending_normalizes_hash(self):
        manager._track_pending(
            "title:v1",
            {"title_id": "0100ABCD", "version": 1, "title_name": "Game"},
            "ABCDEF1234",
            expected_name="Game update",
        )

        pending = manager._state["pending"]["title:v1"]
        self.assertEqual(pending["hash"], "abcdef1234")

    def test_check_completed_matches_hash_case_insensitively(self):
        manager._track_pending(
            "title:v1",
            {"title_id": "0100ABCD", "version": 1, "title_name": "Game"},
            "abcdef1234",
            expected_name="Game update",
        )

        torrent_cfg = {
            "type": "qbittorrent",
            "url": "http://example",
            "username": "",
            "password": "",
            "category": "ownfoil",
            "download_path": "",
        }

        with patch("app.downloads.manager.list_completed", return_value=[
            {"hash": "ABCDEF1234", "path": "/tmp/game.nsp", "name": "Game update"}
        ]), patch("app.downloads.manager._move_completed", return_value="/library/game.nsp"), patch(
            "app.downloads.manager.remove_torrent", return_value=(True, "ok")
        ):
            manager._check_completed(torrent_cfg)

        self.assertNotIn("title:v1", manager._state["pending"])
        self.assertIn("title:v1", manager._state["completed"])


if __name__ == "__main__":
    unittest.main()
