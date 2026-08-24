import unittest
from unittest.mock import patch

from app.downloads import manager


class SearchUpdateOptionsWithoutClientTests(unittest.TestCase):
    def test_search_lists_results_with_only_prowlarr_configured(self):
        fake_results = [{
            'title': 'Game [0100AAAA00000000][v65536]',
            'indexer': 'idx',
            'size': 100,
            'seeders': 5,
            'leechers': 0,
            'download_url': 'magnet:?xt=urn:btih:abc',
            'protocol': 'torrent',
            'age_minutes': 99999,
            'age_label': 'old',
            'published_at': None,
        }]

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def search(self, *args, **kwargs):
                return list(fake_results)

        with patch.object(manager, 'ProwlarrClient', FakeClient), patch.object(
            manager, 'load_settings',
            return_value={'downloads': {'prowlarr': {'url': 'http://prowlarr', 'api_key': 'key'}}},
        ), patch.object(manager.titles_lib, 'load_titledb'), patch.object(
            manager.titles_lib, 'release_titledb'
        ), patch.object(
            manager.titles_lib, 'get_game_info', return_value={'name': 'Game'}
        ):
            ok, message, results = manager.search_update_options('0100AAAA00000000', 65536)

        self.assertTrue(ok)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['protocol'], 'torrent')

    def test_search_still_requires_prowlarr(self):
        with patch.object(manager, 'load_settings', return_value={'downloads': {}}):
            ok, message, results = manager.search_update_options('0100AAAA00000000', 65536)

        self.assertFalse(ok)
        self.assertEqual(message, 'Prowlarr is not configured.')
        self.assertEqual(results, [])


if __name__ == '__main__':
    unittest.main()
