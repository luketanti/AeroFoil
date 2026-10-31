"""Optional metadata providers, kept separate from the primary TitleDB files."""
import logging
import json
import os
import re
import threading
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import requests

from app.constants import TITLEDB_DIR


logger = logging.getLogger('main')
NX_VERSIONS_URL = 'https://raw.githubusercontent.com/16BitWonder/nx-versions/master/versions.txt'
NX_CHANGELOG_URL = NX_VERSIONS_URL.replace('versions.txt', 'FULL-CHANGELOG.md')
_lock = threading.RLock()
_cache_signature = None
_cache = {}


def _read_source_update(source, directory=None):
    try:
        with open(os.path.join(directory or TITLEDB_DIR, f'.{source}-updated'), encoding='utf-8') as handle:
            data = json.load(handle)
        timestamp = datetime.fromisoformat(data['last_updated'])
        if timestamp.tzinfo is None or not re.fullmatch(r'[0-9a-fA-F]{7,40}', data['revision']):
            return {}
        data['last_updated'] = timestamp.astimezone(timezone.utc).isoformat()
        return data
    except (OSError, ValueError, TypeError, KeyError):
        return {}


def record_source_update(source, data, directory=None):
    """Store the upstream commit date for the downloaded source revision."""
    path = os.path.join(directory or TITLEDB_DIR, f'.{source}-updated')
    try:
        with open(path + '.tmp', 'w', encoding='utf-8') as handle:
            json.dump(data, handle)
        os.replace(path + '.tmp', path)
    except OSError:
        logger.warning('Could not record %s upstream timestamp.', source)


def _get_upstream_update(source, revision=None, directory=None):
    """Fetch small commit metadata, using conditional requests for nx-versions."""
    cached = _read_source_update(source, directory)
    if revision and cached.get('revision') == revision:
        return cached
    if source == 'titledb':
        if not re.fullmatch(r'[0-9a-fA-F]{7,40}', str(revision or '')):
            return {}
        url = 'https://api.github.com/repos/blawar/titledb/commits'
        params = {'sha': revision, 'per_page': 1}
    else:
        url = 'https://api.github.com/repos/16BitWonder/nx-versions/commits'
        params = {'path': 'versions.txt', 'sha': 'master', 'per_page': 1}
    headers = {'Accept': 'application/vnd.github+json'}
    if source == 'nx-versions' and cached.get('etag'):
        headers['If-None-Match'] = cached['etag']
    try:
        response = requests.get(url, params=params, headers=headers, timeout=15)
        try:
            if response.status_code == 304 and cached:
                return cached
            response.raise_for_status()
            data = response.json()
            commit = data[0]
            timestamp = datetime.fromisoformat(commit['commit']['committer']['date'].replace('Z', '+00:00'))
            if timestamp.tzinfo is None or not re.fullmatch(r'[0-9a-fA-F]{40}', commit['sha']):
                raise ValueError('Invalid upstream commit metadata')
            if revision and not commit['sha'].startswith(revision):
                raise ValueError('Upstream commit does not match the TitleDB revision')
            return {'revision': revision or commit['sha'],
                    'last_updated': timestamp.astimezone(timezone.utc).isoformat(),
                    'etag': response.headers.get('ETag')}
        finally:
            response.close()
    except (requests.RequestException, OSError, ValueError, TypeError, KeyError, IndexError):
        logger.warning('Could not retrieve %s upstream update timestamp.', source)
        return {}


def update_titledb_source_status(revision, directory):
    data = _get_upstream_update('titledb', revision=revision, directory=directory)
    record_source_update('titledb', data, directory=directory)


def get_metadata_source_status():
    status = {}
    for source in ('titledb', 'nx-versions'):
        data = _read_source_update(source)
        status[source] = {'last_updated': data.get('last_updated')}
    return status


def _file_signature(path):
    stat = os.stat(path)
    return (path, stat.st_mtime_ns, stat.st_size)


def _load_cached_versions(path):
    global _cache_signature, _cache
    signature = _file_signature(path)
    if signature != _cache_signature:
        with open(path, encoding='utf-8') as handle:
            parsed = parse_nx_versions(handle.read())
        _cache = parsed
        _cache_signature = signature
    return _cache


def _conditional_headers(path, url=None):
    try:
        # Only use validators with a valid, unchanged local copy.
        _load_cached_versions(path)
        with open(path + '.meta', encoding='utf-8') as handle:
            meta = json.load(handle)
        if meta.get('signature') != list(_file_signature(path)):
            return {}
        if url and meta.get('url', NX_VERSIONS_URL) != url:
            return {}
        headers = {}
        for key, header in (('etag', 'If-None-Match'), ('last_modified', 'If-Modified-Since')):
            if isinstance(meta.get(key), str) and meta[key]:
                headers[header] = meta[key]
        return headers
    except (OSError, ValueError, AttributeError):
        return {}


def parse_nx_versions(text):
    lines = text.lstrip('\ufeff').splitlines()
    if not lines or lines[0].strip() != 'id|version':
        raise ValueError('Invalid nx-versions header')
    versions = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        match = re.fullmatch(r'([0-9a-fA-F]{16})\|(\d+)', line.strip())
        if not match:
            raise ValueError('Invalid nx-versions row')
        title_id, version = match.groups()
        version = int(version)
        if version > 0xffffffff:
            raise ValueError('Invalid nx-versions version')
        title_id = title_id.upper()
        versions[title_id] = max(version, versions.get(title_id, 0))
    if not versions:
        raise ValueError('Empty nx-versions data')
    return versions


def parse_nx_changelog(text):
    """Index the earliest observation of each added/new version, not the old version."""
    dates = {}
    current_date = None
    for line in text.splitlines():
        line = line.strip()
        heading = re.fullmatch(r'## (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2})(?: \([^)]*\))?', line)
        if heading:
            datetime.strptime(' '.join(heading.groups()), '%Y-%m-%d %H:%M')
            current_date = heading[1]
            continue
        entry = re.fullmatch(r'\[([0-9a-fA-F]{16})\]\[v(\d+)\](?:->\[v(\d+)\])?', line)
        if entry:
            if not current_date:
                raise ValueError('Changelog entry has no date')
            version = int(entry[3] if entry[3] is not None else entry[2])
            if version > 0xffffffff:
                raise ValueError('Invalid changelog version')
            key = (entry[1].upper(), version)
            dates[key] = min(current_date, dates.get(key, current_date))
        elif line.startswith('## ') or re.match(r'\[[0-9a-fA-F]{16}\]', line):
            raise ValueError(f'Invalid changelog row: {line[:120]}')
    if not dates:
        raise ValueError('Empty or invalid nx-versions changelog')
    return dates


def _update_changelog(upstream):
    """Build a persistent date index once per source revision; retain it on failure."""
    path = os.path.join(TITLEDB_DIR, 'nx-versions-dates.sqlite3')
    temp_path = path + '.tmp'
    revision = upstream.get('revision')
    url = NX_CHANGELOG_URL if not revision else NX_CHANGELOG_URL.replace('/master/', f'/{revision}/')
    meta = {}
    try:
        conn = sqlite3.connect(f'{Path(path).resolve().as_uri()}?mode=ro', uri=True)
        try:
            conn.execute('SELECT version FROM dates LIMIT 0')
            meta = dict(conn.execute('SELECT key, value FROM meta'))
            if revision and meta.get('revision') == revision:
                return None
        finally:
            conn.close()
    except (OSError, sqlite3.Error):
        meta = {}
    try:
        headers = {}
        if meta.get('url') == url:
            for key, header in (('etag', 'If-None-Match'), ('last_modified', 'If-Modified-Since')):
                if meta.get(key):
                    headers[header] = meta[key]
        response = requests.get(url, headers=headers, timeout=60)
        try:
            if response.status_code == 304:
                if not headers:
                    raise ValueError('Changelog returned 304 without a cached index')
                return None
            response.raise_for_status()
            dates = parse_nx_changelog(response.content.decode('utf-8-sig'))
            meta = {'url': url, 'revision': revision or '',
                    'etag': response.headers.get('ETag') or '',
                    'last_modified': response.headers.get('Last-Modified') or ''}
        finally:
            response.close()
        conn = sqlite3.connect(temp_path)
        try:
            with conn:
                conn.execute('DROP TABLE IF EXISTS dates')
                conn.execute('DROP TABLE IF EXISTS meta')
                conn.execute('CREATE TABLE dates (app_id TEXT, version INTEGER, date TEXT, PRIMARY KEY (app_id, version))')
                conn.execute('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)')
                conn.executemany('INSERT INTO dates VALUES (?, ?, ?)',
                                 ((app_id, version, date) for (app_id, version), date in dates.items()))
                conn.executemany('INSERT INTO meta VALUES (?, ?)', meta.items())
        finally:
            conn.close()
        os.replace(temp_path, path)
        return None
    except Exception as exc:
        logger.warning('nx-versions changelog refresh failed; keeping cached dates: %s', exc)
        return 'nx-versions dates could not be refreshed. Previously cached dates will still be used.'
    finally:
        try:
            if os.path.isfile(temp_path):
                os.remove(temp_path)
        except OSError:
            pass


def get_version_dates(app_id, app_settings):
    if not (app_settings.get('metadata_sources') or {}).get('nx_versions_enabled', False):
        return {}
    path = os.path.join(TITLEDB_DIR, 'nx-versions-dates.sqlite3')
    try:
        conn = sqlite3.connect(f'{Path(path).resolve().as_uri()}?mode=ro', uri=True)
        try:
            return dict(conn.execute('SELECT version, date FROM dates WHERE app_id = ?',
                                     (str(app_id or '').upper(),)))
        finally:
            conn.close()
    except (OSError, sqlite3.Error):
        return {}


def get_metadata_cache_token():
    """Include optional data changes in library cache invalidation, without reading data."""
    parts = []
    for name in ('nx-versions.txt', 'nx-versions-dates.sqlite3'):
        try:
            _, mtime, size = _file_signature(os.path.join(TITLEDB_DIR, name))
            parts.append(f'{name}:{mtime}:{size}')
        except OSError:
            parts.append(f'{name}:missing')
    return '|'.join(parts)


def update_metadata_sources(app_settings):
    """Refresh enabled providers; failures retain the last validated cache."""
    global _cache_signature, _cache
    if not (app_settings.get('metadata_sources') or {}).get('nx_versions_enabled', False):
        return None
    with _lock:
        path = os.path.join(TITLEDB_DIR, 'nx-versions.txt')
        temp_path = path + '.tmp'
        meta_temp_path = path + '.meta.tmp'
        try:
            upstream = _get_upstream_update('nx-versions')
            # Pin the data to the commit whose date we display.
            url = NX_VERSIONS_URL if not upstream else NX_VERSIONS_URL.replace('/master/', f"/{upstream['revision']}/")
            headers = _conditional_headers(path, url)
            response = requests.get(url, timeout=60, headers=headers)
            try:
                if response.status_code == 304:
                    if not headers:
                        raise ValueError('nx-versions returned 304 without a validated local cache')
                    logger.info('nx-versions metadata is unchanged; using cached data.')
                    if upstream:
                        record_source_update('nx-versions', upstream)
                    return _update_changelog(upstream)
                response.raise_for_status()
                content = response.content.decode('utf-8-sig')
                parsed = parse_nx_versions(content)
                validators = {
                    'etag': response.headers.get('ETag'),
                    'last_modified': response.headers.get('Last-Modified'),
                }
            finally:
                response.close()
            os.makedirs(TITLEDB_DIR, exist_ok=True)
            with open(temp_path, 'w', encoding='utf-8') as handle:
                handle.write(content)
            os.replace(temp_path, path)
            _cache = parsed
            _cache_signature = _file_signature(path)
            validators['signature'] = list(_cache_signature)
            validators['url'] = url
            try:
                with open(meta_temp_path, 'w', encoding='utf-8') as handle:
                    json.dump(validators, handle)
                os.replace(meta_temp_path, path + '.meta')
            except (OSError, TypeError):
                logger.warning('Could not save nx-versions HTTP validators; next refresh will download data.')
            logger.info('nx-versions metadata updated.')
            record_source_update('nx-versions', upstream)
            return _update_changelog(upstream)
        except Exception as exc:
            logger.warning('nx-versions refresh failed; keeping cached data: %s', exc)
            return 'nx-versions could not be refreshed. Any previously cached data will still be used.'
        finally:
            try:
                for cleanup_path in (temp_path, meta_temp_path):
                    if os.path.isfile(cleanup_path):
                        os.remove(cleanup_path)
            except OSError:
                logger.warning('Could not remove nx-versions temporary file.')
    return None


def get_latest_version(app_id, app_settings):
    if not (app_settings.get('metadata_sources') or {}).get('nx_versions_enabled', False):
        return None
    with _lock:
        path = os.path.join(TITLEDB_DIR, 'nx-versions.txt')
        try:
            return _load_cached_versions(path).get(str(app_id or '').upper())
        except (OSError, ValueError):
            return None
