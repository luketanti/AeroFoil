import ast
from collections import Counter
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import Mock

from flask import Flask, jsonify, request
from sqlalchemy import and_, case, func, or_
from app.constants import APP_TYPE_BASE, APP_TYPE_DLC, APP_TYPE_UPD
from app.db import Apps, Files, Titles, app_files, db


class TitlesSortCacheTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        db.init_app(self.app)
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.addCleanup(db.session.remove)
        db.create_all()
        self.addCleanup(db.drop_all)
        self.names = {}
        self.ids = []
        for index, suffix in enumerate(('Delta', 'Alpha', 'Charlie', 'Bravo')):
            tid = f'010000000000{index:04X}'
            self.ids.append(tid)
            self.names[tid] = 'Example Title ' + suffix
            title = Titles(title_id=tid)
            db.session.add(title)
            db.session.flush()
            db.session.add(Apps(title_id=title.id, app_id=tid, app_type=APP_TYPE_BASE,
                                app_version='0', owned=index % 2 == 0))
        db.session.commit()
        self.info = Mock(side_effect=lambda tid: {'id': tid, 'name': self.names[tid]})
        self.clock = Mock(return_value=1000.0)
        self.state = Mock(return_value='fixture-library::fixture-titledb')
        self.ns = dict(
            Apps=Apps, Files=Files, Titles=Titles, app_files=app_files, db=db,
            APP_TYPE_BASE=APP_TYPE_BASE, APP_TYPE_DLC=APP_TYPE_DLC, APP_TYPE_UPD=APP_TYPE_UPD,
            func=func, and_=and_, or_=or_, case=case, request=request, jsonify=jsonify,
            time=SimpleNamespace(time=self.clock), unicodedata=__import__('unicodedata'),
            re=__import__('re'),
            titles=SimpleNamespace(titledb_session=lambda: nullcontext(True),
                                   get_game_info=self.info, get_all_existing_versions=lambda tid: []),
            TITLES_TOTAL_CACHE_TTL_S=300, TITLES_TOTAL_CACHE_MAX_ENTRIES=256,
            titles_total_cache={}, titles_sorted_cache={},
            titles_total_cache_lock=threading.Lock(), titles_sorted_cache_lock=threading.Lock(),
            _user_rating_cap=lambda: (None, True), _get_titledb_aware_state_token=self.state,
            _get_cached_titles_metadata=lambda: {'title_name_map': {k: v.lower() for k, v in self.names.items()}},
            _get_discovery_sections=lambda **kwargs: ([], []),
            _get_cached_library_genres=lambda: [], _is_cyberfoil_request=lambda: False,
        )
        source = ast.parse(Path('app/app.py').read_text(encoding='utf-8'))
        wanted = {'get_all_titles_api', '_get_cached_titles_sorted', '_store_titles_sorted',
                  '_get_cached_titles_total', '_store_titles_total',
                  '_normalize_library_search_text', '_search_matches_normalized_text'}
        nodes = [n for n in source.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
        for node in nodes:
            node.decorator_list = []
        # Execute the actual route and cache helpers without app startup/background jobs.
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'app/app.py', 'exec'), self.ns)

    def get(self, args=''):
        with self.app.test_request_context('/api/titles?per_page=2&' + args):
            return self.ns['get_all_titles_api']().get_json()

    def test_ascending_and_descending_pagination(self):
        first = self.get('page=1')
        second = self.get('page=2')
        descending = self.get('sort=title_desc&page=1')
        self.assertEqual([g['name'] for g in first['games']], ['Example Title Alpha', 'Example Title Bravo'])
        self.assertEqual([g['name'] for g in second['games']], ['Example Title Charlie', 'Example Title Delta'])
        self.assertEqual([g['name'] for g in descending['games']], ['Example Title Delta', 'Example Title Charlie'])
        self.assertEqual(first['total'], 4)

    def test_warm_page_only_looks_up_page_metadata(self):
        self.get('page=1')
        self.info.reset_mock()
        self.get('page=2')
        self.assertEqual(set(call.args[0] for call in self.info.call_args_list), {self.ids[0], self.ids[2]})
        self.assertEqual(self.info.call_count, 2)

    def test_cold_page_does_not_repeat_library_metadata_lookups(self):
        self.get('page=1')
        counts = Counter(call.args[0] for call in self.info.call_args_list)
        self.assertEqual(dict(counts), {tid: 1 for tid in self.ids})

    def test_owned_filter_has_separate_cached_order(self):
        self.get()
        owned = self.get('owned=owned')
        missing = self.get('owned=missing')
        self.assertEqual([g['name'] for g in owned['games']], ['Example Title Charlie', 'Example Title Delta'])
        self.assertEqual([g['name'] for g in missing['games']], ['Example Title Alpha', 'Example Title Bravo'])
        self.assertEqual(owned['total'], 2)
        self.assertEqual(missing['total'], 2)

    def test_search_has_separate_cached_order(self):
        self.get()
        result = self.get('search=Alpha')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['games'][0]['name'], 'Example Title Alpha')

    def test_state_token_change_rebuilds_order(self):
        self.get()
        self.names[self.ids[0]] = 'Example Title Aardvark'
        self.state.return_value = 'fixture-library-updated::fixture-titledb'
        self.assertEqual(self.get()['games'][0]['name'], 'Example Title Aardvark')

    def test_ttl_expiration_rebuilds_order(self):
        self.get()
        self.names[self.ids[0]] = 'Example Title Aardvark'
        self.clock.return_value = 1301.0
        self.assertEqual(self.get()['games'][0]['name'], 'Example Title Aardvark')

    def test_cache_disabled_does_not_store_order(self):
        self.ns['TITLES_TOTAL_CACHE_TTL_S'] = 0
        self.get()
        self.assertEqual(self.ns['titles_sorted_cache'], {})

    def test_empty_page_returns_total_and_no_games(self):
        self.get()
        result = self.get('page=10')
        self.assertEqual(result['total'], 4)
        self.assertEqual(result['games'], [])