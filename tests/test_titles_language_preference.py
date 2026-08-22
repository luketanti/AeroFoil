import unittest
from unittest.mock import patch

from app import settings
from app import titles
from app.constants import BUILTIN_TITLE_MANUAL_OVERRIDES


class TitlesLanguagePreferenceTests(unittest.TestCase):
    def setUp(self):
        titles._reset_titledb_state()
        titles._titles_index_ready = True
        titles._english_titles_index_ready = False
        titles._titles_desc_by_title_id = {}
        titles._titles_images_by_title_id = {}

    def tearDown(self):
        titles._reset_titledb_state()

    def test_get_game_info_prefers_english_metadata_when_enabled(self):
        title_id = "01008EB017F3E000"
        localized_info = {
            'name': 'フィスト 紅蓮城の闇',
            'bannerUrl': 'https://example.invalid/jp-banner.jpg',
            'iconUrl': 'https://example.invalid/jp-icon.jpg',
            'id': title_id,
            'category': 'アクション',
            'nsuId': '111',
            'description': '',
        }
        english_info = {
            'name': 'F.I.S.T.: Forged In Shadow Torch',
            'bannerUrl': 'https://example.invalid/en-banner.jpg',
            'iconUrl': 'https://example.invalid/en-icon.jpg',
            'id': title_id,
            'category': 'Action',
            'nsuId': '222',
            'description': 'English description',
        }
        titles._english_titles_index_ready = True
        titles._titles_images_by_title_id = {
            title_id: ['https://example.invalid/shot-1.jpg']
        }

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'prefer_english_metadata': True, 'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=localized_info,
        ), patch(
            'app.titles._get_english_title_info_from_index',
            return_value=english_info,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'F.I.S.T.: Forged In Shadow Torch')
        self.assertEqual(info['category'], 'Action')
        self.assertEqual(info['description'], 'English description')
        self.assertEqual(info['bannerUrl'], 'https://example.invalid/en-banner.jpg')
        self.assertEqual(info['iconUrl'], 'https://example.invalid/en-icon.jpg')
        self.assertEqual(info['nsuId'], '222')
        self.assertEqual(info['screenshots'], ['https://example.invalid/shot-1.jpg'])

    def test_get_game_info_falls_back_to_localized_metadata_when_english_missing(self):
        title_id = "01008EB017F3E000"
        localized_info = {
            'name': 'Localized Title',
            'bannerUrl': 'https://example.invalid/local-banner.jpg',
            'iconUrl': 'https://example.invalid/local-icon.jpg',
            'id': title_id,
            'category': 'Localized Category',
            'nsuId': '111',
            'description': '',
        }
        titles._english_titles_index_ready = True
        titles._titles_desc_by_title_id = {
            title_id: 'Localized fallback description'
        }

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'prefer_english_metadata': True, 'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=localized_info,
        ), patch(
            'app.titles._get_english_title_info_from_index',
            return_value=None,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'Localized Title')
        self.assertEqual(info['category'], 'Localized Category')
        self.assertEqual(info['description'], 'Localized fallback description')

    def test_normalize_titles_settings_coerces_prefer_english_metadata(self):
        normalized = settings._normalize_titles_settings({
            'region': 'JP',
            'language': 'ja',
            'prefer_english_metadata': 'true',
            'manual_overrides': [],
        })

        self.assertEqual(normalized['region'], 'JP')
        self.assertEqual(normalized['language'], 'ja')
        self.assertTrue(normalized['prefer_english_metadata'])
        self.assertEqual(normalized['manual_overrides'], {})

    def test_normalize_titles_settings_merges_built_in_and_user_overrides(self):
        normalized = settings._normalize_titles_settings({
            'manual_overrides': {
                '0100DEADBEEF0000': {
                    'name': 'Example Custom Title',
                },
            },
        })

        self.assertEqual(normalized['manual_overrides'], {
            '0100DEADBEEF0000': {
                'name': 'Example Custom Title',
                'description': '',
                'iconUrl': '',
                'bannerUrl': '',
                'category': '',
                'nsuId': '',
                'rating': '',
                'screenshots': [],
            },
        })
        self.assertEqual(
            normalized['effective_manual_overrides']['018FCC923D8D0000']['name'],
            BUILTIN_TITLE_MANUAL_OVERRIDES['018FCC923D8D0000']['name'],
        )
        self.assertTrue(normalized['effective_manual_overrides']['018FCC923D8D0000']['description'])
        self.assertTrue(normalized['effective_manual_overrides']['018FCC923D8D0000']['iconUrl'])
        self.assertTrue(normalized['effective_manual_overrides']['018FCC923D8D0000']['bannerUrl'])
        self.assertEqual(
            normalized['effective_manual_overrides']['056783A0CC4A0000']['name'],
            BUILTIN_TITLE_MANUAL_OVERRIDES['056783A0CC4A0000']['name'],
        )
        self.assertTrue(normalized['effective_manual_overrides']['056783A0CC4A0000']['description'])
        self.assertTrue(normalized['effective_manual_overrides']['056783A0CC4A0000']['iconUrl'])
        self.assertTrue(normalized['effective_manual_overrides']['056783A0CC4A0000']['bannerUrl'])
        self.assertEqual(
            normalized['effective_manual_overrides']['0500D22512158000']['name'],
            BUILTIN_TITLE_MANUAL_OVERRIDES['0500D22512158000']['name'],
        )
        self.assertTrue(normalized['effective_manual_overrides']['0500D22512158000']['description'])
        self.assertTrue(normalized['effective_manual_overrides']['0500D22512158000']['iconUrl'])
        self.assertTrue(normalized['effective_manual_overrides']['0500D22512158000']['bannerUrl'])
        self.assertEqual(
            normalized['effective_manual_overrides']['010CAF78CF713000']['name'],
            BUILTIN_TITLE_MANUAL_OVERRIDES['010CAF78CF713000']['name'],
        )
        self.assertTrue(normalized['effective_manual_overrides']['010CAF78CF713000']['description'])
        self.assertTrue(normalized['effective_manual_overrides']['010CAF78CF713000']['iconUrl'])
        self.assertTrue(normalized['effective_manual_overrides']['010CAF78CF713000']['bannerUrl'])
        self.assertEqual(
            normalized['effective_manual_overrides']['0100DEADBEEF0000']['name'],
            'Example Custom Title',
        )

    def test_get_game_info_returns_built_in_override_for_unknown_simpsons_port(self):
        title_id = '018FCC923D8D0000'

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=None,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'The Simpsons: Hit & Run [Port]')
        self.assertEqual(info['id'], f'{title_id} not found in titledb')
        self.assertTrue(info['description'])
        self.assertTrue(info['iconUrl'])
        self.assertTrue(info['bannerUrl'])

    def test_get_game_info_prefers_user_override_over_built_in_override(self):
        title_id = '018FCC923D8D0000'

        with patch(
            'app.titles.load_settings',
            return_value={
                'titles': {
                    'manual_overrides': {
                        title_id: {
                            'name': 'My Simpsons Port Name',
                        },
                    },
                },
            },
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=None,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'My Simpsons Port Name')

    def test_get_game_info_returns_built_in_override_for_unknown_ship_of_harkinian_port(self):
        title_id = '056783A0CC4A0000'

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=None,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'Ship of Harkinian')
        self.assertEqual(info['id'], f'{title_id} not found in titledb')
        self.assertTrue(info['description'])
        self.assertTrue(info['iconUrl'])
        self.assertTrue(info['bannerUrl'])

    def test_get_game_info_returns_built_in_override_for_unknown_sonic_dimensions_port(self):
        title_id = '0500D22512158000'

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=None,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'Sonic Dimensions')
        self.assertEqual(info['id'], f'{title_id} not found in titledb')
        self.assertTrue(info['description'])
        self.assertTrue(info['iconUrl'])
        self.assertTrue(info['bannerUrl'])

    def test_get_game_info_returns_built_in_override_for_unknown_alttp_port(self):
        title_id = '010CAF78CF713000'

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=None,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'The Legend of Zelda - A Link to the Past')
        self.assertEqual(info['id'], f'{title_id} not found in titledb')
        self.assertTrue(info['description'])
        self.assertTrue(info['iconUrl'])
        self.assertTrue(info['bannerUrl'])

    def test_get_game_info_uses_local_file_fallback_when_titledb_entry_is_missing(self):
        title_id = '0A11A11A0A11A11A'
        fallback_info = {
            'name': 'Example Local Title',
            'bannerUrl': f'/api/shop/banner/{title_id}',
            'iconUrl': f'/api/shop/icon/{title_id}',
            'id': title_id,
            'category': '',
            'nsuId': None,
            'description': 'Publisher: Example Studio',
            'screenshots': [],
        }

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=None,
        ), patch(
            'app.titles._build_local_fallback_info',
            return_value=fallback_info,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'Example Local Title')
        self.assertEqual(info['id'], title_id)
        self.assertEqual(info['iconUrl'], f'/api/shop/icon/{title_id}')
        self.assertEqual(info['bannerUrl'], f'/api/shop/banner/{title_id}')

    def test_get_game_info_applies_manual_override_on_top_of_local_file_fallback(self):
        title_id = '0B22B22B0B22B22B'
        fallback_info = {
            'name': 'Example Local Title',
            'bannerUrl': f'/api/shop/banner/{title_id}',
            'iconUrl': f'/api/shop/icon/{title_id}',
            'id': title_id,
            'category': '',
            'nsuId': None,
            'description': 'Publisher: Example Studio',
            'screenshots': [],
        }

        with patch(
            'app.titles.load_settings',
            return_value={
                'titles': {
                    'manual_overrides': {
                        title_id: {
                            'name': 'Example Manual Override Title',
                        },
                    },
                },
            },
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=None,
        ), patch(
            'app.titles._build_local_fallback_info',
            return_value=fallback_info,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'Example Manual Override Title')
        self.assertEqual(info['iconUrl'], f'/api/shop/icon/{title_id}')
        self.assertEqual(info['bannerUrl'], f'/api/shop/banner/{title_id}')

    def test_get_game_info_backfills_missing_titledb_fields_from_local_fallback(self):
        title_id = '010051F0207B2000'
        titledb_info = {
            'name': '',
            'bannerUrl': 'https://example.invalid/titledb-banner.jpg',
            'iconUrl': '',
            'id': title_id,
            'category': '',
            'nsuId': None,
            'description': '',
        }
        fallback_info = {
            'name': 'Example Backfilled Title',
            'bannerUrl': f'/api/shop/banner/{title_id}',
            'iconUrl': f'/api/shop/icon/{title_id}',
            'id': title_id,
            'category': 'Example Category',
            'nsuId': '987',
            'description': 'Publisher: Example Studio',
            'screenshots': ['https://example.invalid/local-shot.jpg'],
        }

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=titledb_info,
        ), patch(
            'app.titles._build_local_fallback_info',
            return_value=fallback_info,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'Example Backfilled Title')
        self.assertEqual(info['bannerUrl'], 'https://example.invalid/titledb-banner.jpg')
        self.assertEqual(info['iconUrl'], f'/api/shop/icon/{title_id}')
        self.assertEqual(info['category'], 'Example Category')
        self.assertEqual(info['nsuId'], '987')
        self.assertEqual(info['description'], 'Publisher: Example Studio')
        self.assertEqual(info['screenshots'], ['https://example.invalid/local-shot.jpg'])

    def test_get_game_info_bridges_dlc_app_lookup_to_base_title_info(self):
        dlc_app_id = '01002E7016C47006'
        base_title_id = '01002E7016C46000'
        base_info = {
            'name': 'Example Base Title',
            'bannerUrl': 'https://example.invalid/base-banner.jpg',
            'iconUrl': 'https://example.invalid/base-icon.jpg',
            'id': base_title_id,
            'category': 'Adventure',
            'nsuId': '123',
            'description': 'Base metadata',
            'screenshots': ['https://example.invalid/shot-1.jpg'],
        }

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            side_effect=lambda tid: base_info if tid == base_title_id else None,
        ), patch(
            'app.titles._candidate_paths_for_local_metadata_lookup',
            return_value=[],
        ), patch(
            'app.titles._related_title_ids_for_lookup',
            return_value=[base_title_id],
        ):
            info = titles.get_game_info(dlc_app_id)

        self.assertEqual(info['name'], 'Example Base Title')
        self.assertEqual(info['id'], dlc_app_id)
        self.assertEqual(info['iconUrl'], f'/api/shop/icon/{dlc_app_id}')
        self.assertEqual(info['bannerUrl'], f'/api/shop/banner/{dlc_app_id}')

    def test_get_game_info_leaves_other_unknown_titles_unrecognized(self):
        title_id = '0BADF00D0BADF00D'

        with patch(
            'app.titles.load_settings',
            return_value={'titles': {'manual_overrides': {}}},
        ), patch(
            'app.titles._get_title_info_from_index',
            return_value=None,
        ):
            info = titles.get_game_info(title_id)

        self.assertEqual(info['name'], 'Unrecognized')
        self.assertEqual(info['id'], f'{title_id} not found in titledb')

    def test_local_fallback_passes_language_and_region_to_local_metadata_extractor(self):
        title_id = '0C33C33C0C33C33C'
        parsed_metadata = {
            'name': 'Example Localized Name',
            'title_id': title_id,
            'version': 0,
            'icon_bytes': b'icon-bytes',
        }

        with patch(
            'app.titles._candidate_paths_for_local_metadata_lookup',
            return_value=['X:\\fixture-root\\example.nsp'],
        ), patch(
            'app.titles._related_title_ids_for_lookup',
            return_value=[],
        ), patch(
            'app.titles._cache_local_media',
            return_value=(True, False),
        ), patch(
            'app.titles._alias_cached_media',
            return_value=(False, False),
        ), patch(
            'app.local_file_metadata.extract_local_metadata',
            return_value=parsed_metadata,
        ) as extractor:
            info = titles._build_local_fallback_info(
                title_id,
                preferred_language='fr',
                preferred_region='CA',
            )

        self.assertEqual(info['name'], 'Example Localized Name')
        self.assertEqual(info['iconUrl'], f'/api/shop/icon/{title_id}')
        extractor.assert_called_once_with(
            'X:\\fixture-root\\example.nsp',
            preferred_language='fr',
            preferred_region='CA',
        )

    def test_local_fallback_cache_is_scoped_by_language_and_region(self):
        title_id = '0D44D44D0D44D44D'
        parsed_metadata = {
            'name': 'Example Cached Name',
            'title_id': title_id,
            'version': 0,
            'icon_bytes': b'icon-bytes',
        }
        with titles._local_file_metadata_cache_lock:
            titles._local_file_metadata_cache.clear()

        with patch(
            'app.titles._candidate_paths_for_local_metadata_lookup',
            return_value=['X:\\fixture-root\\example.nsp'],
        ), patch(
            'app.titles._related_title_ids_for_lookup',
            return_value=[],
        ), patch(
            'app.titles._cache_local_media',
            return_value=(True, False),
        ), patch(
            'app.titles._alias_cached_media',
            return_value=(False, False),
        ), patch(
            'app.local_file_metadata.extract_local_metadata',
            return_value=parsed_metadata,
        ) as extractor:
            titles._build_local_fallback_info(
                title_id,
                preferred_language='en',
                preferred_region='US',
            )
            titles._build_local_fallback_info(
                title_id,
                preferred_language='fr',
                preferred_region='CA',
            )
            titles._build_local_fallback_info(
                title_id,
                preferred_language='en',
                preferred_region='US',
            )

        self.assertEqual(extractor.call_count, 2)


if __name__ == '__main__':
    unittest.main()
