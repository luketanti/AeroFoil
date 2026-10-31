import unittest
from datetime import datetime


_IMPORT_ERROR = None
try:
    from app.app import (
        _build_rotating_recommendations,
        _recommendation_rotation_key,
        _shop_sections_payload_matches_rotation,
    )
except ModuleNotFoundError as exc:
    _IMPORT_ERROR = exc


class DiscoveryRecommendationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _IMPORT_ERROR is not None:
            raise unittest.SkipTest(f"Missing dependency for discovery recommendation tests: {_IMPORT_ERROR}")

    @staticmethod
    def _items(count):
        return [
            {
                'title_id': f'{index:016X}',
                'app_id': f'{index:016X}',
                'file_id': count - index,
                'download_count': index % 4,
            }
            for index in range(count)
        ]

    def test_rotation_key_uses_calendar_day(self):
        self.assertEqual(
            _recommendation_rotation_key(datetime(2026, 9, 16, 23, 59)),
            '2026-09-16',
        )

    def test_recommendations_are_stable_within_a_day(self):
        items = self._items(30)
        first = _build_rotating_recommendations(items, limit=12, rotation_key='2026-09-16')
        second = _build_rotating_recommendations(items, limit=12, rotation_key='2026-09-16')
        self.assertEqual(first, second)

    def test_recommendations_rotate_between_days(self):
        items = self._items(30)
        first = _build_rotating_recommendations(items, limit=12, rotation_key='2026-09-16')
        second = _build_rotating_recommendations(items, limit=12, rotation_key='2026-09-17')
        self.assertNotEqual(
            [item['app_id'] for item in first],
            [item['app_id'] for item in second],
        )

    def test_recommendations_avoid_visible_new_titles_when_possible(self):
        items = self._items(30)
        recommended = _build_rotating_recommendations(
            items,
            limit=12,
            rotation_key='2026-09-16',
            newest_visible_count=12,
        )
        newest_ids = {item['app_id'] for item in items[:12]}
        recommended_ids = {item['app_id'] for item in recommended}
        self.assertTrue(newest_ids.isdisjoint(recommended_ids))

    def test_small_library_still_returns_each_title_once(self):
        items = self._items(5)
        recommended = _build_rotating_recommendations(
            items,
            limit=12,
            rotation_key='2026-09-16',
        )
        self.assertCountEqual(
            [item['app_id'] for item in recommended],
            [item['app_id'] for item in items],
        )

    def test_cached_payload_must_match_current_rotation(self):
        payload = {'rotation_key': '2026-09-16', 'sections': []}
        self.assertTrue(_shop_sections_payload_matches_rotation(payload, '2026-09-16'))
        self.assertFalse(_shop_sections_payload_matches_rotation(payload, '2026-09-17'))
        self.assertFalse(_shop_sections_payload_matches_rotation({'sections': []}, '2026-09-16'))


if __name__ == '__main__':
    unittest.main()
