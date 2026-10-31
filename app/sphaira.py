"""Read-only Ownfoil protocol used by Sphaira's native library menu."""
from functools import lru_cache
import logging
import hashlib
import io
import os
import uuid
from urllib.parse import urlsplit

from PIL import Image, ImageOps
import requests

from graphql import GraphQLError, build_schema, parse, validate, execute_sync
from sqlalchemy.orm import selectinload

from app import titles
from app.db import Apps, Titles

logger = logging.getLogger('main')
SCREENSHOT_SIZES = {'CLIENT': (720, 405), 'SCREEN': (1280, 720), 'THUMB': (320, 180)}
MAX_SCREENSHOT_BYTES = 16 * 1024 * 1024


def screenshot_source(value):
    url = str(value or '').strip()
    if url.startswith('//'):
        url = 'https:' + url
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme in ('http', 'https') and parts.netloc:
        return url
    return None


def cached_screenshot(cache_dir, title_id, position, source, size):
    """Cache a bounded JPEG rendition; never forward shop credentials upstream."""
    digest = hashlib.sha256(source.encode('utf-8')).hexdigest()[:24]
    filename = f'{title_id}_{position}_{digest}_{size.lower()}.jpg'
    path = os.path.join(cache_dir, filename)
    if os.path.isfile(path):
        return path
    with requests.get(source, stream=True, timeout=(5, 20)) as response:
        response.raise_for_status()
        data = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            data.extend(chunk)
            if len(data) > MAX_SCREENSHOT_BYTES:
                raise ValueError('Screenshot exceeds download size limit.')
    os.makedirs(cache_dir, exist_ok=True)
    temporary = path + '.' + uuid.uuid4().hex + '.tmp'
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.width * image.height > 20_000_000:
                raise ValueError('Screenshot exceeds pixel limit.')
            image = ImageOps.exif_transpose(image)
            image.thumbnail(SCREENSHOT_SIZES[size], Image.Resampling.LANCZOS)
            image.convert('RGB').save(temporary, format='JPEG', quality=85, optimize=True)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
    return path

SCHEMA = build_schema('''
scalar BigInt
enum AppType { BASE UPDATE DLC }
enum ImageSize { THUMB CLIENT SCREEN }
enum SortField { NAME ADDED_AT RELEASE_DATE }
enum SortDirection { ASC DESC }
input OrderBy { field: SortField!, direction: SortDirection = ASC }
input StringFilter { in: [String!], notIn: [String!] }
input AppFilter { appId: StringFilter, titleId: StringFilter }
type Image { url: String!, local: Boolean! }
type Version { version: BigInt!, displayVersion: String, releaseDate: String }
type App {
    appId: String!, titleId: String!, appVersion: BigInt!, displayVersion: String
    latestOwnedVersion: Version, downloadUrl: String, downloadExtension: String
    downloadSize: BigInt, titledb: Title, title: Title
}
type AppConnection { total: Int!, items: [App!]! }
type Title {
    name: String, publisher: String, intro: String, description: String
    releaseDate: String, category: [String!]!, numberOfPlayers: String
    size: String, rating: String, region: String
    icon(size: ImageSize = THUMB): Image
    banner(size: ImageSize = CLIENT): Image
    screenshots(size: ImageSize = CLIENT): [Image!]!
    availableVersions: [Version!]!
    apps(owned: Boolean, appType: [AppType!]): [App!]!
}
type Query {
    apps(owned: Boolean, appType: [AppType!], groupByAppId: Boolean = false,
         filter: AppFilter, search: String, orderBy: OrderBy,
         page: Int = 1, pageSize: Int = 100): AppConnection!
    title(titleId: ID!): Title
}
''')
SCHEMA.type_map['BigInt'].serialize = int


class Catalogue:
    """Request-local metadata and file permissions; never shared between users."""
    def __init__(self, cap, block_unrated, title_allowed, file_blocked):
        self.cap = cap
        self.block_unrated = block_unrated
        self.title_allowed = title_allowed
        self.file_blocked = file_blocked
        self.metadata = {}
        self.downloads = {}
        self.row_cache = {}

    def info(self, title_id):
        if title_id not in self.metadata:
            # get_game_info supplies language preferences and local fallbacks;
            # the index also holds optional catalogue fields used on detail pages.
            metadata = dict(titles._get_title_info_from_index(title_id) or {}) if titles._titles_index_ready else {}
            metadata.update(titles.get_game_info(title_id) or {})
            self.metadata[title_id] = metadata
        return self.metadata[title_id]

    def visible(self, title_id):
        return self.title_allowed(self.cap, self.info(title_id).get('rating'), self.block_unrated)

    def download(self, app):
        if app.id not in self.downloads:
            candidates = sorted(app.files, key=lambda f: (bool(f.multicontent), int(f.size or 0), f.id))
            self.downloads[app.id] = next((f for f in candidates if self.cap is None or
                not self.file_blocked(f.id, self.cap, self.block_unrated)), None)
        return self.downloads[app.id]

    def rows(self, owned=None, app_type=None, title_id=None):
        key = (owned, tuple(app_type or []), title_id)
        if key in self.row_cache:
            return self.row_cache[key]
        query = Apps.query.options(selectinload(Apps.title), selectinload(Apps.files))
        if owned is not None:
            query = query.filter(Apps.owned == owned)
        if app_type:
            query = query.filter(Apps.app_type.in_(app_type))
        if title_id is not None:
            query = query.join(Titles).filter(Titles.title_id == title_id)
        # Only expose owned content that can be delivered to this caller.
        rows = [a for a in query.all() if self.visible(a.title.title_id) and
                (not a.owned or self.download(a) is not None)]
        self.row_cache[key] = rows
        return rows

    def app_value(self, row):
        file = self.download(row) if row.owned else None
        return {
            'appId': row.app_id, 'titleId': row.title.title_id,
            'appVersion': int(row.app_version or 0), 'displayVersion': None,
            'downloadUrl': f'/api/get_game/{file.id}' if file else None,
            'downloadExtension': (file.extension or '').lstrip('.').lower() if file else None,
            'downloadSize': int(file.size or 0) if file else None,
            'titledb': {'_title_id': row.app_id}, 'title': {'_title_id': row.title.title_id},
            '_row': row,
        }

    def apps(self, owned=None, appType=None, groupByAppId=False, filter=None,
             search=None, orderBy=None, page=1, pageSize=100):
        rows = self.rows(owned, appType)
        for field, attr in (('appId', 'app_id'), ('titleId', None)):
            predicate = (filter or {}).get(field) or {}
            include, exclude = predicate.get('in'), predicate.get('notIn')
            rows = [a for a in rows if
                    (not include or (getattr(a, attr) if attr else a.title.title_id) in include) and
                    (not exclude or (getattr(a, attr) if attr else a.title.title_id) not in exclude)]
        if search:
            term = search.casefold()
            rows = [a for a in rows if any(term in str(v or '').casefold() for v in
                    (a.app_id, a.title.title_id, self.info(a.title.title_id).get('name')))]
        if groupByAppId:
            grouped = {}
            for row in rows:
                if row.app_id not in grouped or int(row.app_version or 0) > int(grouped[row.app_id].app_version or 0):
                    grouped[row.app_id] = row
            rows = list(grouped.values())
        order = orderBy or {}
        field = order.get('field')
        def key(row):
            if field == 'NAME':
                value = str(self.info(row.title.title_id).get('name') or row.app_id).casefold()
            elif field == 'RELEASE_DATE':
                value = str(self.info(row.title.title_id).get('releaseDate') or '')
            else:
                # AeroFoil has no added_at column; file insertion order is stable.
                value = max((f.id for f in row.files), default=row.id)
            return value, row.app_id, row.id
        rows.sort(key=key, reverse=order.get('direction') == 'DESC')
        size = max(1, min(100 if pageSize is None else pageSize, 1000))
        start = (max(1 if page is None else page, 1) - 1) * size
        return {'total': len(rows), 'items': [self.app_value(a) for a in rows[start:start + size]]}


def _title_field(source, info, **args):
    catalog = info.context
    title_id = source['_title_id']
    metadata = catalog.info(title_id)
    field = info.field_name
    if field == 'apps':
        return [catalog.app_value(a) for a in catalog.rows(args.get('owned'), args.get('appType'), title_id)]
    if field in ('icon', 'banner'):
        url = metadata.get(field + 'Url')
        if not url or 'placehold.it' in str(url):
            return None
        return {'url': f'/api/shop/{field}/{title_id}', 'local': True}
    if field == 'screenshots':
        images = []
        size = args.get('size') or 'CLIENT'
        for position, value in enumerate(metadata.get('screenshots') or []):
            url = str(value or '').strip()
            if screenshot_source(url):
                images.append({'url': f'/api/shop/screenshot/{title_id}/{position}?size={size.lower()}', 'local': True})
            elif url.startswith('/') and not url.startswith('//'):
                images.append({'url': url, 'local': True})
        return images
    if field == 'availableVersions':
        return [{'version': v['version'], 'releaseDate': v.get('release_date')}
                for v in titles.get_all_existing_versions(title_id)]
    if field == 'category':
        value = metadata.get('category') or []
        return value if isinstance(value, list) else [value]
    value = metadata.get(field)
    return str(value) if value is not None else None


def _latest_owned(source, info):
    row = source['_row']
    rows = [a for a in info.context.rows(True, ['UPDATE'] if row.app_type == 'BASE' else [row.app_type])
            if a.title.title_id == row.title.title_id]
    if row.app_type != 'BASE':
        rows = [a for a in rows if a.app_id == row.app_id]
    if not rows:
        return None
    return {'version': max(int(a.app_version or 0) for a in rows), 'displayVersion': None}


def _resolve_title(source, info, titleId):
    title_id = str(titleId).upper()
    if not Titles.query.filter_by(title_id=title_id).first() or not info.context.visible(title_id):
        return None
    return {'_title_id': title_id}


SCHEMA.query_type.fields['apps'].resolve = lambda source, info, **args: info.context.apps(**args)
SCHEMA.query_type.fields['title'].resolve = _resolve_title
SCHEMA.type_map['App'].fields['latestOwnedVersion'].resolve = _latest_owned
for field in SCHEMA.type_map['Title'].fields.values():
    field.resolve = _title_field


@lru_cache(maxsize=128)
def _document(query):
    document = parse(query, max_tokens=5000)
    errors = validate(SCHEMA, document)
    if errors:
        return document, errors
    fragments = {d.name.value: d for d in document.definitions if d.kind == 'fragment_definition'}
    count = 0
    def depth(selection, level=0):
        nonlocal count
        if level > 15:
            raise ValueError('Query exceeds maximum depth of 15.')
        for node in selection.selections:
            count += 1
            if count > 2000:
                raise ValueError('Query exceeds maximum selection count of 2000.')
            if node.kind == 'fragment_spread':
                depth(fragments[node.name.value].selection_set, level)
            elif node.selection_set:
                depth(node.selection_set, level + 1)
    for definition in document.definitions:
        if definition.kind == 'operation_definition':
            depth(definition.selection_set)
    return document, errors


def execute(payload, catalogue):
    if not isinstance(payload, dict) or not isinstance(payload.get('query'), str):
        return {'errors': [{'message': 'Expected a GraphQL query string.'}]}
    query = payload['query']
    if len(query) > 64000:
        return {'errors': [{'message': 'Query is too large.'}]}
    variables = payload.get('variables')
    operation = payload.get('operationName')
    if variables is not None and not isinstance(variables, dict):
        return {'errors': [{'message': 'Variables must be an object.'}]}
    if operation is not None and not isinstance(operation, str):
        return {'errors': [{'message': 'Operation name must be a string.'}]}
    try:
        document, errors = _document(query)
        if errors:
            return {'errors': [{'message': e.message} for e in errors]}
        result = execute_sync(SCHEMA, document, context_value=catalogue,
                              variable_values=variables, operation_name=operation)
        output = {'data': result.data}
        if result.errors:
            output['errors'] = []
            for error in result.errors:
                if error.original_error:
                    logger.error('Sphaira resolver failed', exc_info=error.original_error)
                    message = 'Could not load the library.'
                else:
                    message = error.message
                output['errors'].append({'message': message})
        return output
    except (GraphQLError, ValueError, RecursionError) as error:
        return {'errors': [{'message': str(error)}]}
    except Exception:
        logger.exception('Could not execute Sphaira query')
        return {'errors': [{'message': 'Could not execute query.'}]}
