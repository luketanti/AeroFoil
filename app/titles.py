import os
import sys
import re
import json
import sqlite3
import gc
import ctypes
import unicodedata
import requests
import threading
import time
from contextlib import contextmanager

from app import titledb
from app.constants import *
from app.utils import *
from app.settings import *
from pathlib import Path
import logging

# Retrieve main logger
logger = logging.getLogger('main')


class _KeysPlaceholder:
    keys_loaded = False


# Keep module-level names for compatibility with other modules (e.g. library.py),
# but delay nsz import until needed so app startup does not invoke nsz.
Keys = _KeysPlaceholder()
Pfs0 = None
Xci = None
Nsp = None
Nca = None
Type = None
factory = None
_nsz_import_attempted = False
_nsz_import_ok = False


def _ensure_nsz_loaded(require_fs=False):
    global Keys
    global Pfs0
    global Xci
    global Nsp
    global Nca
    global Type
    global factory
    global _nsz_import_attempted
    global _nsz_import_ok

    if _nsz_import_ok and (not require_fs or factory is not None):
        return True

    if _nsz_import_attempted and not _nsz_import_ok:
        return False

    _nsz_import_attempted = True
    try:
        from nsz.nut import Keys as _Keys
        Keys = _Keys
        if require_fs:
            from nsz.Fs import Pfs0 as _Pfs0, Xci as _Xci, Nsp as _Nsp, Nca as _Nca, Type as _Type, factory as _factory
            Pfs0 = _Pfs0
            Xci = _Xci
            Nsp = _Nsp
            Nca = _Nca
            Type = _Type
            factory = _factory
            try:
                Pfs0.Print.silent = True
            except Exception:
                pass
        _nsz_import_ok = True
        return True
    except Exception as e:
        logger.warning(f"NSZ modules are not available yet: {e}")
        _nsz_import_ok = False
        return False


def keys_loaded():
    if not _ensure_nsz_loaded(require_fs=False):
        return False
    return bool(getattr(Keys, 'keys_loaded', False))

app_id_regex = r"\[([0-9A-Fa-f]{16})\]"
version_regex = r"\[v(\d+)\]"

# Global variables for TitleDB data
identification_in_progress_count = 0
_titles_db_loaded = False
_cnmts_db = None
_titles_db = None
_titles_by_title_id = None
_titles_desc_db = None
_titles_desc_by_title_id = None
_titles_images_by_title_id = None
_versions_db = None
_versions_txt_db = None
_cnmts_index_ready = False
_titles_index_ready = False
_versions_index_ready = False
_versions_index_file = os.path.join(TITLEDB_DIR, 'versions.index.sqlite3')
_cnmts_index_file = os.path.join(TITLEDB_DIR, 'cnmts.index.sqlite3')
_titles_index_file = os.path.join(TITLEDB_DIR, 'titles.index.sqlite3')
_titledb_lock = threading.Lock()
_missing_titledb_log_lock = threading.Lock()
_missing_titledb_last_log = {}
_MISSING_TITLE_LOG_TTL_S = 3600
_TITLEDB_STATE_WARN_TTL_S = 60
_titledb_state_warn_last_log = {}
_MISSING_FILES_RECOVERY_COOLDOWN_S = 60
_missing_files_recovery_last_attempt_ts = 0.0
_missing_files_recovery_in_progress = False
_titledb_data_signature = None
_title_lookup_cache = {}
_title_lookup_cache_lock = threading.Lock()
_TITLE_LOOKUP_CACHE_MAX = 4096

try:
    _libc = ctypes.CDLL("libc.so.6")
    _malloc_trim = getattr(_libc, "malloc_trim", None)
    if _malloc_trim is not None:
        _malloc_trim.argtypes = [ctypes.c_size_t]
        _malloc_trim.restype = ctypes.c_int
except Exception:
    _malloc_trim = None

class CorruptedTitleDBFileError(Exception):
    def __init__(self, file_path, label, original_error):
        self.file_path = file_path
        self.label = label
        self.original_error = original_error
        super().__init__(f"Invalid JSON in {label} ({file_path}): {original_error}")

def _reset_titledb_state():
    global _cnmts_db
    global _titles_db
    global _titles_by_title_id
    global _versions_db
    global _versions_txt_db
    global _cnmts_index_ready
    global _titles_index_ready
    global _versions_index_ready
    global _titles_desc_db
    global _titles_desc_by_title_id
    global _titles_images_by_title_id
    global _titles_db_loaded

    _cnmts_db = None
    _titles_db = None
    _titles_by_title_id = None
    _versions_db = None
    _versions_txt_db = None
    _cnmts_index_ready = False
    _titles_index_ready = False
    _versions_index_ready = False
    _titles_desc_db = None
    _titles_desc_by_title_id = None
    _titles_images_by_title_id = None
    _titles_db_loaded = False
    with _title_lookup_cache_lock:
        _title_lookup_cache.clear()

def _load_json_file(path, label):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise CorruptedTitleDBFileError(path, label, e) from e

def _versions_source_signature(path):
    stat = os.stat(path)
    mtime_ns = getattr(stat, 'st_mtime_ns', int(stat.st_mtime * 1e9))
    return f"{int(stat.st_size)}:{int(mtime_ns)}"

def _open_versions_index_db(path):
    conn = sqlite3.connect(path, timeout=30)
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def _release_process_memory():
    try:
        gc.collect()
    except Exception:
        pass
    if _malloc_trim is not None:
        try:
            _malloc_trim(0)
        except Exception:
            pass

def _normalize_title_search_text(value):
    text = str(value or '')
    try:
        text = unicodedata.normalize('NFKD', text)
        text = text.encode('ascii', 'ignore').decode('ascii')
    except Exception:
        pass
    text = re.sub(r"[^A-Za-z0-9\s]+", " ", text)
    return re.sub(r"\s+", " ", text).strip().lower()

def _read_versions_index_meta(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (str(key),)).fetchone()
    return row[0] if row else None

def _ensure_versions_index(versions_file):
    global _versions_index_ready
    expected_signature = _versions_source_signature(versions_file)

    conn = None
    try:
        conn = _open_versions_index_db(_versions_index_file)
        with conn:
            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS versions ("
                "title_id TEXT NOT NULL, "
                "version INTEGER NOT NULL, "
                "release_date TEXT, "
                "PRIMARY KEY (title_id, version))"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_versions_title_id ON versions(title_id)")
            signature = _read_versions_index_meta(conn, "source_signature")
            rows_count = _read_versions_index_meta(conn, "rows_count")
            if signature == expected_signature and rows_count is not None:
                _versions_index_ready = True
                return True
    except Exception as e:
        logger.warning(f"Failed to validate versions index, rebuilding: {e}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    logger.info("Building versions index from versions.json...")
    data = _load_json_file(versions_file, 'versions')
    if not isinstance(data, dict):
        raise ValueError("Invalid versions.json structure: expected object at root")

    tmp_db = _versions_index_file + ".tmp"
    try:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)
    except Exception:
        pass

    rows_count = 0
    conn = _open_versions_index_db(tmp_db)
    try:
        with conn:
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE versions ("
                "title_id TEXT NOT NULL, "
                "version INTEGER NOT NULL, "
                "release_date TEXT, "
                "PRIMARY KEY (title_id, version))"
            )
            conn.execute("CREATE INDEX idx_versions_title_id ON versions(title_id)")

            batch = []
            batch_size = 5000
            for title_id, versions in data.items():
                if not isinstance(versions, dict):
                    continue
                title_key = str(title_id or '').strip().lower()
                if not title_key:
                    continue
                for version_key, release_date in versions.items():
                    try:
                        version_int = int(version_key)
                    except Exception:
                        continue
                    batch.append((title_key, version_int, release_date))
                    if len(batch) >= batch_size:
                        conn.executemany(
                            "INSERT OR REPLACE INTO versions (title_id, version, release_date) VALUES (?, ?, ?)",
                            batch,
                        )
                        rows_count += len(batch)
                        batch.clear()
            if batch:
                conn.executemany(
                    "INSERT OR REPLACE INTO versions (title_id, version, release_date) VALUES (?, ?, ?)",
                    batch,
                )
                rows_count += len(batch)

            conn.executemany(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                [
                    ("source_signature", expected_signature),
                    ("rows_count", str(int(rows_count))),
                ],
            )
    finally:
        try:
            conn.close()
        except Exception:
            pass

    os.replace(tmp_db, _versions_index_file)
    _versions_index_ready = True
    logger.info("Versions index ready with %s rows.", rows_count)
    _release_process_memory()
    return True

def _versions_index_row_count():
    if not _versions_index_ready:
        return 0
    try:
        conn = _open_versions_index_db(_versions_index_file)
        try:
            value = _read_versions_index_meta(conn, "rows_count")
            return int(value) if value is not None else 0
        finally:
            conn.close()
    except Exception:
        return 0

def _ensure_cnmts_index(cnmts_file):
    global _cnmts_index_ready
    expected_signature = _versions_source_signature(cnmts_file)

    conn = None
    try:
        conn = _open_versions_index_db(_cnmts_index_file)
        with conn:
            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cnmts ("
                "app_id TEXT NOT NULL, "
                "version_key TEXT NOT NULL, "
                "sort_order INTEGER NOT NULL, "
                "version_int INTEGER, "
                "title_type INTEGER, "
                "other_application_id TEXT, "
                "PRIMARY KEY (app_id, version_key))"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cnmts_app_sort ON cnmts(app_id, sort_order DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cnmts_title_type_other ON cnmts(title_type, other_application_id)")
            signature = _read_versions_index_meta(conn, "source_signature")
            rows_count = _read_versions_index_meta(conn, "rows_count")
            if signature == expected_signature and rows_count is not None:
                _cnmts_index_ready = True
                return True
    except Exception as e:
        logger.warning(f"Failed to validate cnmts index, rebuilding: {e}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    logger.info("Building cnmts index from cnmts.json...")
    data = _load_json_file(cnmts_file, 'cnmts')
    if not isinstance(data, dict):
        raise ValueError("Invalid cnmts.json structure: expected object at root")

    tmp_db = _cnmts_index_file + ".tmp"
    try:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)
    except Exception:
        pass

    conn = _open_versions_index_db(tmp_db)
    try:
        with conn:
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE cnmts ("
                "app_id TEXT NOT NULL, "
                "version_key TEXT NOT NULL, "
                "sort_order INTEGER NOT NULL, "
                "version_int INTEGER, "
                "title_type INTEGER, "
                "other_application_id TEXT, "
                "PRIMARY KEY (app_id, version_key))"
            )
            conn.execute("CREATE INDEX idx_cnmts_app_sort ON cnmts(app_id, sort_order DESC)")
            conn.execute("CREATE INDEX idx_cnmts_title_type_other ON cnmts(title_type, other_application_id)")

            batch = []
            batch_size = 5000
            for app_id, versions in data.items():
                if not isinstance(versions, dict):
                    continue
                app_key = str(app_id or '').strip().lower()
                if not app_key:
                    continue
                order = 0
                for version_key, version_desc in versions.items():
                    order += 1
                    version_key_str = str(version_key or '').strip()
                    if not version_key_str:
                        continue
                    try:
                        version_int = int(version_key_str)
                    except Exception:
                        version_int = None
                    title_type = None
                    other_application_id = None
                    if isinstance(version_desc, dict):
                        try:
                            title_type = int(version_desc.get('titleType'))
                        except Exception:
                            title_type = None
                        other_value = str(version_desc.get('otherApplicationId') or '').strip().lower()
                        if other_value:
                            other_application_id = other_value
                    batch.append((app_key, version_key_str, int(order), version_int, title_type, other_application_id))
                    if len(batch) >= batch_size:
                        conn.executemany(
                            "INSERT OR REPLACE INTO cnmts "
                            "(app_id, version_key, sort_order, version_int, title_type, other_application_id) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            batch,
                        )
                        batch.clear()

            if batch:
                conn.executemany(
                    "INSERT OR REPLACE INTO cnmts "
                    "(app_id, version_key, sort_order, version_int, title_type, other_application_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    batch,
                )

            row_count = conn.execute("SELECT COUNT(*) FROM cnmts").fetchone()[0]
            app_count = conn.execute("SELECT COUNT(DISTINCT app_id) FROM cnmts").fetchone()[0]
            conn.executemany(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                [
                    ("source_signature", expected_signature),
                    ("rows_count", str(int(row_count))),
                    ("apps_count", str(int(app_count))),
                ],
            )
    finally:
        try:
            conn.close()
        except Exception:
            pass

    os.replace(tmp_db, _cnmts_index_file)
    _cnmts_index_ready = True
    logger.info("cnmts index ready with %s rows.", row_count)
    _release_process_memory()
    return True

def _ensure_titles_index(region_titles_file):
    global _titles_index_ready
    expected_signature = _versions_source_signature(region_titles_file)

    conn = None
    try:
        conn = _open_versions_index_db(_titles_index_file)
        with conn:
            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS titles ("
                "title_id TEXT PRIMARY KEY, "
                "name TEXT, "
                "banner_url TEXT, "
                "icon_url TEXT, "
                "category TEXT, "
                "nsu_id TEXT, "
                "description TEXT, "
                "search_hay TEXT, "
                "sort_order INTEGER NOT NULL)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_titles_sort_order ON titles(sort_order)")
            signature = _read_versions_index_meta(conn, "source_signature")
            rows_count = _read_versions_index_meta(conn, "rows_count")
            if signature == expected_signature and rows_count is not None:
                _titles_index_ready = True
                return True
    except Exception as e:
        logger.warning(f"Failed to validate titles index, rebuilding: {e}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    logger.info("Building titles index from region titles...")
    data = _load_json_file(region_titles_file, 'region_titles')
    if not isinstance(data, dict):
        raise ValueError("Invalid region titles file: expected object at root")

    tmp_db = _titles_index_file + ".tmp"
    try:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)
    except Exception:
        pass

    conn = _open_versions_index_db(tmp_db)
    try:
        with conn:
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE titles ("
                "title_id TEXT PRIMARY KEY, "
                "name TEXT, "
                "banner_url TEXT, "
                "icon_url TEXT, "
                "category TEXT, "
                "nsu_id TEXT, "
                "description TEXT, "
                "search_hay TEXT, "
                "sort_order INTEGER NOT NULL)"
            )
            conn.execute("CREATE INDEX idx_titles_sort_order ON titles(sort_order)")

            batch = []
            batch_size = 5000
            order = 0
            for item in data.values():
                if not isinstance(item, dict):
                    continue
                title_id = str(item.get('id') or '').strip().upper()
                if not title_id:
                    continue
                order += 1
                name = str(item.get('name') or '').strip()
                banner_url = str(item.get('bannerUrl') or '').strip()
                icon_url = str(item.get('iconUrl') or '').strip()
                category = str(item.get('category') or '').strip()
                nsu_id_raw = item.get('nsuId')
                nsu_id = None if nsu_id_raw is None else str(nsu_id_raw)
                description = str(item.get('description') or '').strip() or None
                search_hay = _normalize_title_search_text(f"{title_id} {name}")
                batch.append((
                    title_id,
                    name,
                    banner_url,
                    icon_url,
                    category,
                    nsu_id,
                    description,
                    search_hay,
                    int(order),
                ))
                if len(batch) >= batch_size:
                    conn.executemany(
                        "INSERT OR REPLACE INTO titles "
                        "(title_id, name, banner_url, icon_url, category, nsu_id, description, search_hay, sort_order) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        batch,
                    )
                    batch.clear()
            if batch:
                conn.executemany(
                    "INSERT OR REPLACE INTO titles "
                    "(title_id, name, banner_url, icon_url, category, nsu_id, description, search_hay, sort_order) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    batch,
                )

            row_count = conn.execute("SELECT COUNT(*) FROM titles").fetchone()[0]
            conn.executemany(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                [
                    ("source_signature", expected_signature),
                    ("rows_count", str(int(row_count))),
                ],
            )
    finally:
        try:
            conn.close()
        except Exception:
            pass

    os.replace(tmp_db, _titles_index_file)
    _titles_index_ready = True
    logger.info("titles index ready with %s rows.", row_count)
    with _title_lookup_cache_lock:
        _title_lookup_cache.clear()
    _release_process_memory()
    return True

def _cnmts_index_row_count():
    if not _cnmts_index_ready:
        return 0
    try:
        conn = _open_versions_index_db(_cnmts_index_file)
        try:
            value = _read_versions_index_meta(conn, "rows_count")
            return int(value) if value is not None else 0
        finally:
            conn.close()
    except Exception:
        return 0

def _cnmts_index_app_count():
    if not _cnmts_index_ready:
        return 0
    try:
        conn = _open_versions_index_db(_cnmts_index_file)
        try:
            value = _read_versions_index_meta(conn, "apps_count")
            return int(value) if value is not None else 0
        finally:
            conn.close()
    except Exception:
        return 0

def _titles_index_row_count():
    if not _titles_index_ready:
        return 0
    try:
        conn = _open_versions_index_db(_titles_index_file)
        try:
            value = _read_versions_index_meta(conn, "rows_count")
            return int(value) if value is not None else 0
        finally:
            conn.close()
    except Exception:
        return 0

def _recover_corrupted_titledb_file(app_settings, file_path, label):
    rel_path = os.path.relpath(file_path, start=APP_DIR) if os.path.isabs(file_path) else file_path
    logger.warning(
        "Detected corrupted TitleDB file (%s: %s). Removing file and forcing re-download.",
        label,
        rel_path
    )
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
    except Exception as e:
        logger.warning("Failed to remove corrupted TitleDB file %s: %s", rel_path, e)
    titledb.update_titledb(app_settings)

def _required_titledb_files(app_settings):
    return [
        ('cnmts', os.path.join(TITLEDB_DIR, 'cnmts.json')),
        ('region_titles', os.path.join(TITLEDB_DIR, titledb.get_region_titles_file(app_settings))),
        ('versions', os.path.join(TITLEDB_DIR, 'versions.json')),
        ('versions_txt', os.path.join(TITLEDB_DIR, 'versions.txt')),
    ]

def _missing_titledb_files(required_files):
    return [(label, path) for label, path in (required_files or []) if not os.path.isfile(path)]

def _build_titledb_data_signature(required_files):
    parts = []
    for label, path in (required_files or []):
        try:
            stat = os.stat(path)
            parts.append(f"{label}:{os.path.basename(path)}:{int(stat.st_size)}:{int(getattr(stat, 'st_mtime_ns', int(stat.st_mtime * 1e9)))}")
        except Exception:
            parts.append(f"{label}:{os.path.basename(path)}:missing")
    return "|".join(parts)

def _warn_titledb_state_once(key, message, *args):
    now = time.time()
    should_log = False
    with _missing_titledb_log_lock:
        last_logged = float(_titledb_state_warn_last_log.get(key, 0.0))
        if (now - last_logged) >= _TITLEDB_STATE_WARN_TTL_S:
            _titledb_state_warn_last_log[key] = now
            should_log = True
        if len(_titledb_state_warn_last_log) > 128:
            cutoff = now - (_TITLEDB_STATE_WARN_TTL_S * 2)
            stale_keys = [k for k, ts in _titledb_state_warn_last_log.items() if ts < cutoff]
            for stale_key in stale_keys:
                _titledb_state_warn_last_log.pop(stale_key, None)
    if should_log:
        logger.warning(message, *args)

def _recover_missing_titledb_files_background(app_settings):
    global _missing_files_recovery_in_progress
    try:
        titledb.update_titledb(app_settings)
    except Exception as e:
        logger.warning(f"Failed to recover missing TitleDB files: {e}")
    finally:
        with _titledb_lock:
            _missing_files_recovery_in_progress = False

def get_titledb_cache_token():
    with _titledb_lock:
        return str(_titledb_data_signature or 'missing')


def _ensure_titledb_descriptions_file(app_settings):
    """Ensure the descriptions index file exists locally."""
    try:
        desc_url, desc_filename = titledb.get_descriptions_url(app_settings)
        desc_path = os.path.join(TITLEDB_DIR, desc_filename)
        if os.path.isfile(desc_path):
            return desc_path

        os.makedirs(TITLEDB_DIR, exist_ok=True)
        tmp_path = desc_path + '.tmp'
        try:
            logger.info(f"Downloading {desc_filename} from {desc_url}...")
            r = requests.get(desc_url, stream=True, timeout=120)
            r.raise_for_status()
            with open(tmp_path, 'wb') as fp:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        fp.write(chunk)
            os.replace(tmp_path, desc_path)
            return desc_path
        finally:
            try:
                if os.path.isfile(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Failed to ensure TitleDB descriptions: {e}")
        return None

def getDirsAndFiles(path):
    entries = os.listdir(path)
    allFiles = []
    allDirs = []

    for entry in entries:
        fullPath = os.path.join(path, entry)
        if os.path.isdir(fullPath):
            allDirs.append(fullPath)
            dirs, files = getDirsAndFiles(fullPath)
            allDirs += dirs
            allFiles += files
        elif fullPath.split('.')[-1] in ALLOWED_EXTENSIONS:
            allFiles.append(fullPath)
    return allDirs, allFiles

def get_app_id_from_filename(filename):
    app_id_match = re.search(app_id_regex, filename)
    return app_id_match[1] if app_id_match is not None else None

def get_version_from_filename(filename):
    version_match = re.search(version_regex, filename)
    return version_match[1] if version_match is not None else None

def get_title_id_from_app_id(app_id, app_type):
    base_id = app_id[:-3]
    if app_type == APP_TYPE_UPD:
        title_id = base_id + '000'
    elif app_type == APP_TYPE_DLC:
        title_id = hex(int(base_id, base=16) - 1)[2:].rjust(len(base_id), '0') + '000'
    return title_id.upper()

def get_file_size(filepath):
    return os.path.getsize(filepath)

def get_file_info(filepath):
    filedir, filename = os.path.split(filepath)
    extension = filename.split('.')[-1]
    
    compressed = False
    if extension in ['nsz', 'xcz']:
        compressed = True

    return {
        'filepath': filepath,
        'filedir': filedir,
        'filename': filename,
        'extension': extension,
        'compressed': compressed,
        'size': get_file_size(filepath),
    }

def identify_appId(app_id):
    app_id = app_id.lower()

    def _fallback_identification():
        logger.warning(f'{app_id} not in cnmts index, fallback to default identification.')
        if app_id.endswith('000'):
            app_type_local = APP_TYPE_BASE
            title_id_local = app_id
        elif app_id.endswith('800'):
            app_type_local = APP_TYPE_UPD
            title_id_local = get_title_id_from_app_id(app_id, app_type_local)
        else:
            app_type_local = APP_TYPE_DLC
            title_id_local = get_title_id_from_app_id(app_id, app_type_local)
        return title_id_local.upper(), app_type_local

    global _cnmts_index_ready
    if not _cnmts_index_ready:
        _warn_titledb_state_once('cnmts_not_loaded', "cnmts index is not loaded. Call load_titledb first.")
        return None, None

    try:
        conn = _open_versions_index_db(_cnmts_index_file)
        try:
            row = conn.execute(
                "SELECT title_type, other_application_id "
                "FROM cnmts WHERE app_id = ? "
                "ORDER BY sort_order DESC LIMIT 1",
                (app_id,),
            ).fetchone()
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed querying cnmts index for {app_id.upper()}: {e}")
        return _fallback_identification()

    if not row:
        return _fallback_identification()

    title_type, other_application_id = row
    if title_type == 128:
        return app_id.upper(), APP_TYPE_BASE
    if title_type == 129:
        app_type = APP_TYPE_UPD
        if other_application_id:
            return str(other_application_id).upper(), app_type
        return get_title_id_from_app_id(app_id, app_type).upper(), app_type
    if title_type == 130:
        app_type = APP_TYPE_DLC
        if other_application_id:
            return str(other_application_id).upper(), app_type
        return get_title_id_from_app_id(app_id, app_type).upper(), app_type

    logger.warning(f'{app_id} has unknown title type in cnmts index, fallback to default identification.')
    return _fallback_identification()

def load_titledb():
    global _cnmts_db
    global _titles_db
    global _titles_by_title_id
    global _versions_db
    global _versions_txt_db
    global _cnmts_index_ready
    global _titles_index_ready
    global _versions_index_ready
    global _titles_desc_db
    global _titles_desc_by_title_id
    global _titles_images_by_title_id
    global identification_in_progress_count
    global _titles_db_loaded
    global _missing_files_recovery_last_attempt_ts
    global _missing_files_recovery_in_progress
    global _titledb_data_signature
    with _titledb_lock:
        if _titles_db_loaded:
            identification_in_progress_count += 1
            return True

        logger.info("Loading TitleDBs into memory...")
        app_settings = load_settings()

        # Ensure directory exists before any recovery attempt.
        if not os.path.isdir(TITLEDB_DIR):
            try:
                os.makedirs(TITLEDB_DIR, exist_ok=True)
            except Exception:
                pass

        required_files = _required_titledb_files(app_settings)
        missing_files = _missing_titledb_files(required_files)
        if missing_files:
            missing_parts = [f"{label}:{os.path.basename(path)}" for label, path in missing_files]
            _titledb_data_signature = "missing|" + ",".join(sorted(missing_parts))
            missing_names = ", ".join([os.path.basename(path) for _, path in missing_files])
            _warn_titledb_state_once('missing_required_files', "Missing required TitleDB file(s): %s", missing_names)
            now = time.time()
            should_attempt_recovery = (
                not _missing_files_recovery_in_progress and
                (now - float(_missing_files_recovery_last_attempt_ts or 0.0))
                >= float(_MISSING_FILES_RECOVERY_COOLDOWN_S)
            )
            if should_attempt_recovery:
                _missing_files_recovery_last_attempt_ts = now
                _missing_files_recovery_in_progress = True
                try:
                    threading.Thread(
                        target=_recover_missing_titledb_files_background,
                        args=(app_settings,),
                        daemon=True
                    ).start()
                except Exception:
                    _missing_files_recovery_in_progress = False
            return False

        cnmts_file = dict(required_files).get('cnmts')
        region_titles_file = dict(required_files).get('region_titles')
        versions_file = dict(required_files).get('versions')
        versions_txt_file = dict(required_files).get('versions_txt')

        for attempt in range(2):
            try:
                _versions_db = None
                _cnmts_index_ready = False
                _titles_index_ready = False
                _versions_index_ready = False
                _ensure_versions_index(versions_file)
                _ensure_cnmts_index(cnmts_file)
                _ensure_titles_index(region_titles_file)

                _cnmts_db = None
                _titles_db = None
                _titles_by_title_id = None

                _titles_desc_db = None
                _titles_desc_by_title_id = None
                _titles_images_by_title_id = None
                try:
                    _, desc_filename = titledb.get_descriptions_url(app_settings)
                    desc_path = os.path.join(TITLEDB_DIR, desc_filename)
                    if not os.path.isfile(desc_path):
                        desc_path = _ensure_titledb_descriptions_file(app_settings)
                    if desc_path and os.path.isfile(desc_path):
                        _titles_desc_db = _load_json_file(desc_path, 'descriptions')

                        by_id = {}
                        images_by_id = {}
                        if isinstance(_titles_desc_db, dict):
                            for item in _titles_desc_db.values():
                                if not isinstance(item, dict):
                                    continue
                                tid = (item.get('id') or '').strip().upper()
                                if not tid:
                                    continue
                                desc = (item.get('description') or '').strip()
                                if desc:
                                    by_id[tid] = desc

                                screenshots = item.get('screenshots')
                                if isinstance(screenshots, list):
                                    urls = [str(u).strip() for u in screenshots if str(u or '').strip()]
                                    if urls:
                                        images_by_id[tid] = urls[:12]
                        _titles_desc_by_title_id = by_id
                        _titles_images_by_title_id = images_by_id
                        # Release raw descriptions payload after deriving lightweight indexes.
                        _titles_desc_db = None
                except CorruptedTitleDBFileError:
                    # Descriptions are optional for core operation; skip hard-failing on this file.
                    raise
                except Exception as e:
                    logger.warning(f"Failed to load TitleDB descriptions: {e}")

                _versions_txt_db = {}
                with open(versions_txt_file, encoding="utf-8") as f:
                    for line in f:
                        line_strip = line.rstrip("\n")
                        app_id, _, version = line_strip.split('|')
                        if not version:
                            version = "0"
                        _versions_txt_db[app_id] = version

                _titles_db_loaded = True
                _titledb_data_signature = _build_titledb_data_signature(required_files)
                identification_in_progress_count += 1
                logger.info("TitleDBs loaded.")
                _release_process_memory()
                return True
            except CorruptedTitleDBFileError as e:
                _reset_titledb_state()
                if attempt == 0:
                    try:
                        _recover_corrupted_titledb_file(app_settings, e.file_path, e.label)
                    except Exception as recovery_error:
                        logger.error(f"Failed to recover corrupted TitleDB files: {recovery_error}")
                        return False
                    continue
                logger.error(f"Failed to load TitleDB files after recovery attempt: {e}")
                return False
            except Exception as e:
                _reset_titledb_state()
                logger.error(f"Failed to load TitleDB files: {e}")
                return False

def release_titledb():
    global identification_in_progress_count

    with _titledb_lock:
        if identification_in_progress_count <= 0:
            if identification_in_progress_count < 0:
                logger.warning("TitleDB refcount was negative, resetting to 0.")
            identification_in_progress_count = 0
        else:
            identification_in_progress_count -= 1

    unload_titledb()

@contextmanager
def titledb_session():
    loaded = load_titledb()
    try:
        yield loaded
    finally:
        if loaded:
            release_titledb()

def get_titledb_diagnostics():
    with _titledb_lock:
        return {
            'loaded': bool(_titles_db_loaded),
            'cache_token': str(_titledb_data_signature or 'missing'),
            'refcount': int(identification_in_progress_count or 0),
            'sizes': {
                'cnmts': _cnmts_index_app_count() if _cnmts_index_ready else (len(_cnmts_db) if isinstance(_cnmts_db, dict) else 0),
                'cnmts_index_rows': _cnmts_index_row_count(),
                'cnmts_index_apps': _cnmts_index_app_count(),
                'cnmts_index_ready': bool(_cnmts_index_ready),
                'titles_by_title_id': _titles_index_row_count() if _titles_index_ready else (len(_titles_by_title_id) if isinstance(_titles_by_title_id, dict) else 0),
                'titles_index_rows': _titles_index_row_count(),
                'titles_index_ready': bool(_titles_index_ready),
                'titles_desc_by_title_id': len(_titles_desc_by_title_id) if isinstance(_titles_desc_by_title_id, dict) else 0,
                'titles_images_by_title_id': len(_titles_images_by_title_id) if isinstance(_titles_images_by_title_id, dict) else 0,
                'versions': _versions_index_row_count(),
                'versions_index_ready': bool(_versions_index_ready),
                'versions_txt': len(_versions_txt_db) if isinstance(_versions_txt_db, dict) else 0,
            }
        }

@debounce(30)
def unload_titledb():
    global _cnmts_db
    global _titles_db
    global _titles_by_title_id
    global _versions_db
    global _versions_txt_db
    global _cnmts_index_ready
    global _titles_index_ready
    global _versions_index_ready
    global _titles_desc_db
    global _titles_desc_by_title_id
    global _titles_images_by_title_id
    global identification_in_progress_count
    global _titles_db_loaded

    with _titledb_lock:
        if identification_in_progress_count > 0:
            logger.debug('Identification still in progress, not unloading TitleDB.')
            return
        if not _titles_db_loaded:
            return

        logger.info("Unloading TitleDBs from memory...")
        _cnmts_db = None
        _titles_db = None
        _titles_by_title_id = None
        _versions_db = None
        _versions_txt_db = None
        _cnmts_index_ready = False
        _titles_index_ready = False
        _versions_index_ready = False
        _titles_desc_db = None
        _titles_desc_by_title_id = None
        _titles_images_by_title_id = None
        _titles_db_loaded = False
        with _title_lookup_cache_lock:
            _title_lookup_cache.clear()
        logger.info("TitleDBs unloaded.")

def identify_file_from_filename(filename):
    title_id = None
    app_id = None
    app_type = None
    version = None
    errors = []

    app_id = get_app_id_from_filename(filename)
    if app_id is None:
        errors.append('Could not determine App ID from filename, pattern [APPID] not found. Title ID and Type cannot be derived.')
    else:
        title_id, app_type = identify_appId(app_id)

    version = get_version_from_filename(filename)
    if version is None:
        errors.append('Could not determine version from filename, pattern [vVERSION] not found.')
    
    error = ' '.join(errors)
    return app_id, title_id, app_type, version, error

def get_cnmts(container):
    if not _ensure_nsz_loaded(require_fs=True):
        return []
    cnmts = []
    if isinstance(container, Nsp.Nsp):
        try:
            cnmt = container.cnmt()
            cnmts.append(cnmt)
        except Exception:
            logger.warning('CNMT section not found in Nsp.')
    elif isinstance(container, Xci.Xci):
        secure_partition = container.hfs0['secure']
        for nspf in secure_partition:
            if isinstance(nspf, Nca.Nca) and nspf.header.contentType == Type.Content.META:
                cnmts.append(nspf)
    return cnmts

def extract_meta_from_cnmt(cnmt_sections):
    if not _ensure_nsz_loaded(require_fs=True):
        return []
    contents = []
    for section in cnmt_sections:
        if isinstance(section, Pfs0.Pfs0):
            cnmt = section.getCnmt()
            title_type = APP_TYPE_MAP[cnmt.titleType]
            title_id = cnmt.titleId.upper()
            version = cnmt.version
            contents.append((title_type, title_id, version))
    return contents

def identify_file_from_cnmt(filepath):
    if not _ensure_nsz_loaded(require_fs=True):
        raise RuntimeError('NSZ modules are not available.')
    contents = []
    container = factory(Path(filepath).resolve())
    try:
        container.open(filepath, 'rb', meta_only=True)
    except TypeError as e:
        # Backward compatibility: some nsz builds do not support meta_only.
        if 'meta_only' not in str(e):
            raise
        logger.debug('meta_only is not supported by this nsz build; using full container open.')
        container.open(filepath, 'rb')
    try:
        for cnmt_sections in get_cnmts(container):
            contents += extract_meta_from_cnmt(cnmt_sections)
    finally:
        container.close()

    return contents

def identify_file(filepath):
    filename = os.path.split(filepath)[-1]
    contents = []
    success = True
    error = ''
    if keys_loaded():
        identification = 'cnmt'
        try:
            cnmt_contents = identify_file_from_cnmt(filepath)
            if not cnmt_contents:
                error = 'No content found in NCA containers.'
                success = False
            else:
                for content in cnmt_contents:
                    app_type, app_id, version = content
                    if app_type != APP_TYPE_BASE:
                        # need to get the title ID from cnmts
                        title_id, app_type = identify_appId(app_id)
                    else:
                        title_id = app_id
                    contents.append((title_id, app_type, app_id, version))
        except Exception as e:
            logger.error(f'Could not identify file {filepath} from metadata: {e}')
            error = str(e)
            success = False

    else:
        identification = 'filename'
        app_id, title_id, app_type, version, error = identify_file_from_filename(filename)
        if not error:
            contents.append((title_id, app_type, app_id, version))
        else:
            success = False

    if contents:
        contents = [{
            'title_id': c[0],
            'app_id': c[2],
            'type': c[1],
            'version': c[3],
            } for c in contents]
    return identification, success, contents, error

def _get_manual_title_override(title_id):
    try:
        settings = load_settings()
        overrides = (settings.get('titles') or {}).get('manual_overrides') or {}
        return overrides.get(str(title_id or '').strip().upper()) or {}
    except Exception:
        return {}

def _apply_manual_title_override(title_id, info):
    out = dict(info or {})
    override = _get_manual_title_override(title_id)
    if not isinstance(override, dict) or not override:
        return out

    for key in ('name', 'description', 'iconUrl', 'bannerUrl'):
        value = str(override.get(key) or '').strip()
        if value:
            out[key] = value
    screenshots = override.get('screenshots')
    if isinstance(screenshots, list) and screenshots:
        out['screenshots'] = [str(u).strip() for u in screenshots if str(u or '').strip()][:12]
    return out

def _get_title_info_from_index(title_key):
    with _title_lookup_cache_lock:
        cached = _title_lookup_cache.get(title_key)
        if isinstance(cached, dict):
            return dict(cached)

    try:
        conn = _open_versions_index_db(_titles_index_file)
        try:
            row = conn.execute(
                "SELECT name, banner_url, icon_url, title_id, category, nsu_id, description "
                "FROM titles WHERE title_id = ? LIMIT 1",
                (title_key,),
            ).fetchone()
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed querying titles index for {title_key}: {e}")
        return None

    if not row:
        return None

    info = {
        'name': row[0] or '',
        'bannerUrl': row[1] or '',
        'iconUrl': row[2] or '',
        'id': row[3] or title_key,
        'category': row[4] or '',
        'nsuId': row[5],
        'description': row[6],
    }
    with _title_lookup_cache_lock:
        _title_lookup_cache[title_key] = info
        if len(_title_lookup_cache) > _TITLE_LOOKUP_CACHE_MAX:
            try:
                _title_lookup_cache.pop(next(iter(_title_lookup_cache)))
            except Exception:
                _title_lookup_cache.clear()
    return dict(info)

def get_game_info(title_id):
    global _titles_db
    global _titles_by_title_id
    global _titles_index_ready
    global _titles_desc_by_title_id
    global _titles_images_by_title_id
    if not _titles_index_ready and _titles_db is None and _titles_by_title_id is None:
        _warn_titledb_state_once('titles_not_loaded', "titles index is not loaded. Call load_titledb first.")
        # Return default structure so games can still be displayed
        return _apply_manual_title_override(title_id, {
            'name': 'Unrecognized',
            'bannerUrl': '//placehold.it/400x200',
            'iconUrl': '',
            'id': title_id,
            'category': '',
            'nsuId': None,
            'description': None,
            'screenshots': [],
        })

    try:
        title_key = str(title_id or '').strip().upper()
        title_info = _get_title_info_from_index(title_key) if _titles_index_ready else (_titles_by_title_id or {}).get(title_key)
        if title_info is None and isinstance(_titles_db, dict):
            for item in _titles_db.values():
                if not isinstance(item, dict):
                    continue
                if (item.get('id') or '').strip().upper() == title_key:
                    title_info = item
                    break
        if title_info is None:
            raise KeyError(title_id)

        description = (title_info.get('description') or '').strip() or None
        if not description and isinstance(_titles_desc_by_title_id, dict):
            try:
                description = (_titles_desc_by_title_id.get(title_key) or '').strip() or None
            except Exception:
                pass

        screenshots = []
        if isinstance(_titles_images_by_title_id, dict):
            try:
                screenshots = _titles_images_by_title_id.get(title_key) or []
            except Exception:
                screenshots = []
        return _apply_manual_title_override(title_id, {
            'name': title_info['name'],
            'bannerUrl': title_info['bannerUrl'],
            'iconUrl': title_info['iconUrl'],
            'id': title_info['id'],
            'category': title_info['category'],
            'nsuId': title_info.get('nsuId'),
            'description': description,
            'screenshots': screenshots,
        })
    except Exception:
        normalized_title_id = str(title_id or '').strip().upper()
        now = time.time()
        should_log = False
        with _missing_titledb_log_lock:
            last_logged = float(_missing_titledb_last_log.get(normalized_title_id, 0.0))
            if (now - last_logged) >= _MISSING_TITLE_LOG_TTL_S:
                _missing_titledb_last_log[normalized_title_id] = now
                should_log = True
            if len(_missing_titledb_last_log) > 5000:
                cutoff = now - (_MISSING_TITLE_LOG_TTL_S * 2)
                stale_keys = [k for k, ts in _missing_titledb_last_log.items() if ts < cutoff]
                for key in stale_keys:
                    _missing_titledb_last_log.pop(key, None)
        if should_log:
            logger.warning("Title ID not found in titledb: %s", normalized_title_id or title_id)
        return _apply_manual_title_override(title_id, {
            'name': 'Unrecognized',
            'bannerUrl': '//placehold.it/400x200',
            'iconUrl': '',
            'id': title_id + ' not found in titledb',
            'category': '',
            'nsuId': None,
            'description': None,
            'screenshots': [],
        })


def search_titles(query, limit=20):
    """Search the loaded TitleDB by name or title id.

    Returns a list of lightweight title dicts suitable for UI autocomplete.
    """
    global _titles_db
    global _titles_by_title_id
    global _titles_index_ready
    if not _titles_index_ready and _titles_db is None and _titles_by_title_id is None:
        _warn_titledb_state_once('titles_not_loaded', "titles index is not loaded. Call load_titledb first.")
        return []

    q = _normalize_title_search_text(query)
    if not q:
        return []

    try:
        limit = int(limit)
    except Exception:
        limit = 20
    limit = max(1, min(limit, 100))

    if _titles_index_ready:
        like_query = f"%{q}%"
        try:
            conn = _open_versions_index_db(_titles_index_file)
            try:
                rows = conn.execute(
                    "SELECT title_id, name, category, icon_url, banner_url "
                    "FROM titles "
                    "WHERE search_hay LIKE ? "
                    "ORDER BY sort_order ASC "
                    "LIMIT ?",
                    (like_query, int(limit)),
                ).fetchall()
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"Failed searching titles index for '{q}': {e}")
            rows = []

        out = []
        for row in rows:
            out.append({
                'id': (row[0] or '').upper(),
                'name': (row[1] or '').strip() or 'Unrecognized',
                'category': row[2] or '',
                'iconUrl': row[3] or '',
                'bannerUrl': row[4] or '',
            })
        return out

    out = []
    seen_ids = set()
    source = _titles_by_title_id if isinstance(_titles_by_title_id, dict) else _titles_db
    for item in (source or {}).values():
        try:
            tid = (item.get('id') or '').upper()
            name = (item.get('name') or '').strip()
        except Exception:
            continue
        if not tid or tid in seen_ids:
            continue
        hay = _normalize_title_search_text(f"{tid} {name}")
        if q not in hay:
            continue
        out.append({
            'id': tid,
            'name': name or 'Unrecognized',
            'category': item.get('category') or '',
            'iconUrl': item.get('iconUrl') or '',
            'bannerUrl': item.get('bannerUrl') or '',
        })
        seen_ids.add(tid)
        if len(out) >= limit:
            break
    return out

def get_update_number(version):
    return int(version)//65536

def get_game_latest_version(all_existing_versions):
    return max(v['version'] for v in all_existing_versions)

def get_all_existing_versions(titleid):
    global _versions_index_ready
    if not _versions_index_ready:
        _warn_titledb_state_once('versions_not_loaded', "versions index is not loaded. Call load_titledb first.")
        return []

    if not titleid:
        logger.warning("get_all_existing_versions called with None or empty titleid")
        return []

    titleid = titleid.lower()
    try:
        conn = _open_versions_index_db(_versions_index_file)
        try:
            rows = conn.execute(
                "SELECT version, release_date FROM versions WHERE title_id = ? ORDER BY version ASC",
                (titleid,),
            ).fetchall()
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed querying versions index for {titleid.upper()}: {e}")
        return []

    out = []
    for version, release_date in rows:
        try:
            version_int = int(version)
        except Exception:
            continue
        out.append(
            {
                'version': version_int,
                'update_number': get_update_number(version_int),
                'release_date': release_date,
            }
        )
    return out

def get_all_app_existing_versions(app_id):
    global _cnmts_index_ready
    if not _cnmts_index_ready:
        _warn_titledb_state_once('cnmts_not_loaded', "cnmts index is not loaded. Call load_titledb first.")
        return None

    if not app_id:
        logger.warning("get_all_app_existing_versions called with None or empty app_id")
        return None

    app_id = app_id.lower()
    try:
        conn = _open_versions_index_db(_cnmts_index_file)
        try:
            rows = conn.execute(
                "SELECT version_key FROM cnmts WHERE app_id = ?",
                (app_id,),
            ).fetchall()
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed querying cnmts index for app versions {app_id.upper()}: {e}")
        return None
    if not rows:
        return None
    versions = [str(r[0]) for r in rows if r and r[0] is not None]
    return sorted(versions) if versions else None
    
def get_app_id_version_from_versions_txt(app_id):
    global _versions_txt_db
    if _versions_txt_db is None:
        _warn_titledb_state_once('versions_txt_not_loaded', "versions_txt_db is not loaded. Call load_titledb first.")
        return None
    if not app_id:
        logger.warning("get_app_id_version_from_versions_txt called with None or empty app_id")
        return None
    return _versions_txt_db.get(app_id, None)
    
def get_all_existing_dlc(title_id):
    global _cnmts_index_ready
    if not _cnmts_index_ready:
        _warn_titledb_state_once('cnmts_not_loaded', "cnmts index is not loaded. Call load_titledb first.")
        return []

    if not title_id:
        logger.warning("get_all_existing_dlc called with None or empty title_id")
        return []

    title_id = title_id.lower()
    try:
        conn = _open_versions_index_db(_cnmts_index_file)
        try:
            rows = conn.execute(
                "SELECT DISTINCT app_id FROM cnmts "
                "WHERE title_type = 130 AND other_application_id = ? "
                "ORDER BY app_id ASC",
                (title_id,),
            ).fetchall()
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed querying cnmts DLC entries for {title_id.upper()}: {e}")
        return []
    return [str(r[0]).upper() for r in rows if r and r[0]]
