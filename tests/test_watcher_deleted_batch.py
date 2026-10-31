import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.app import on_library_change


def _event(event_type, src_path, directory='/games', dest_path=None):
    return SimpleNamespace(
        type=event_type,
        src_path=src_path,
        dest_path=dest_path,
        directory=directory,
    )


class WatcherDeletedBatchTests(unittest.TestCase):
    @patch('app.app.post_library_change')
    @patch('app.app.delete_files_by_filepaths_batch', return_value=(3, 3))
    def test_deleted_events_are_cleared_in_one_batch(self, batch_mock, post_mock):
        events = [
            _event('deleted', '/games/a.nsp'),
            _event('deleted', '/games/b.nsp'),
            # Watchdog can emit duplicate events for the same path.
            _event('deleted', '/games/a.nsp'),
            # Moves out of the library are deletions from the library's view.
            _event('moved', '/games/c.nsp', dest_path='/outside/c.nsp'),
        ]

        on_library_change(events)

        batch_mock.assert_called_once_with(
            ['/games/a.nsp', '/games/b.nsp', '/games/c.nsp'], commit=True
        )
        post_mock.assert_called_once_with()

    @patch('app.app.post_library_change')
    @patch('app.app.delete_files_by_filepaths_batch', return_value=(0, 0))
    def test_no_rebuild_when_nothing_was_in_the_database(self, batch_mock, post_mock):
        on_library_change([_event('deleted', '/games/unknown.nsp')])

        batch_mock.assert_called_once_with(['/games/unknown.nsp'], commit=True)
        post_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
