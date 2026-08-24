import threading
import time
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app import titledb


class TitledbUpdateSerializationTests(unittest.TestCase):
    def test_concurrent_update_runs_are_serialized(self):
        active = {"count": 0, "max": 0}
        counter_lock = threading.Lock()

        def fake_update_files(app_settings):
            with counter_lock:
                active["count"] += 1
                active["max"] = max(active["max"], active["count"])
            time.sleep(0.05)
            with counter_lock:
                active["count"] -= 1

        with TemporaryDirectory() as tmp_dir, patch.object(
            titledb, "TITLEDB_DIR", tmp_dir
        ), patch.object(
            titledb, "update_titledb_files", side_effect=fake_update_files
        ):
            threads = [
                threading.Thread(target=titledb.update_titledb, args=({},))
                for _ in range(3)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        # Only one run may touch the download/temp files at a time.
        self.assertEqual(active["max"], 1)

    def test_update_errors_propagate_and_release_the_lock(self):
        with TemporaryDirectory() as tmp_dir, patch.object(
            titledb, "TITLEDB_DIR", tmp_dir
        ), patch.object(
            titledb, "update_titledb_files", side_effect=ValueError("boom")
        ):
            with self.assertRaises(ValueError):
                titledb.update_titledb({})

        # The lock must be free again for the next run; a non-blocking acquire
        # fails fast instead of hanging the suite if it ever leaks.
        self.assertTrue(titledb._update_titledb_run_lock.acquire(blocking=False))
        titledb._update_titledb_run_lock.release()


if __name__ == "__main__":
    unittest.main()
