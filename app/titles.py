import os
import sys
import re
import json
import unicodedata
import requests
import threading
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
_titledb_lock = threading.Lock()

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
    global _titles_desc_db
    global _titles_desc_by_title_id
    global _titles_images_by_title_id
    global _titles_db_loaded

    _cnmts_db = None
    _titles_db = None
    _titles_by_title_id = None
    _versions_db = None
    _versions_txt_db = None
    _titles_desc_db = None
    _titles_desc_by_title_id = None
    _titles_images_by_title_id = None
    _titles_db_loaded = False

def _load_json_file(path, label):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise CorruptedTitleDBFileError(path, label, e) from e

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
    
    global _cnmts_db
    if _cnmts_db is None:
        logger.warning("cnmts_db is not loaded. Call load_titledb first.")
        return None, None

    if app_id in _cnmts_db:
        app_id_keys = list(_cnmts_db[app_id].keys())
        if len(app_id_keys):
            app = _cnmts_db[app_id][app_id_keys[-1]]
            
            if app['titleType'] == 128:
                app_type = APP_TYPE_BASE
                title_id = app_id.upper()
            elif app['titleType'] == 129:
                app_type = APP_TYPE_UPD
                if 'otherApplicationId' in app:
                    title_id = app['otherApplicationId'].upper()
                else:
                    title_id = get_title_id_from_app_id(app_id, app_type)
            elif app['titleType'] == 130:
                app_type = APP_TYPE_DLC
                if 'otherApplicationId' in app:
                    title_id = app['otherApplicationId'].upper()
                else:
                    title_id = get_title_id_from_app_id(app_id, app_type)
        else:
            logger.warning(f'{app_id} has no keys in cnmts_db, fallback to default identification.')
            if app_id.endswith('000'):
                app_type = APP_TYPE_BASE
                title_id = app_id
            elif app_id.endswith('800'):
                app_type = APP_TYPE_UPD
                title_id = get_title_id_from_app_id(app_id, app_type)
            else:
                app_type = APP_TYPE_DLC
                title_id = get_title_id_from_app_id(app_id, app_type)
    else:
        logger.warning(f'{app_id} not in cnmts_db, fallback to default identification.')
        if app_id.endswith('000'):
            app_type = APP_TYPE_BASE
            title_id = app_id
        elif app_id.endswith('800'):
            app_type = APP_TYPE_UPD
            title_id = get_title_id_from_app_id(app_id, app_type)
        else:
            app_type = APP_TYPE_DLC
            title_id = get_title_id_from_app_id(app_id, app_type)
    
    return title_id.upper(), app_type

def load_titledb():
    global _cnmts_db
    global _titles_db
    global _titles_by_title_id
    global _versions_db
    global _versions_txt_db
    global _titles_desc_db
    global _titles_desc_by_title_id
    global _titles_images_by_title_id
    global identification_in_progress_count
    global _titles_db_loaded
    with _titledb_lock:
        if _titles_db_loaded:
            identification_in_progress_count += 1
            return True

        logger.info("Loading TitleDBs into memory...")
        app_settings = load_settings()

        # Check if TitleDB directory exists and has required files.
        if not os.path.isdir(TITLEDB_DIR):
            logger.warning(f"TitleDB directory {TITLEDB_DIR} does not exist. TitleDB files need to be downloaded first.")
            return False

        cnmts_file = os.path.join(TITLEDB_DIR, 'cnmts.json')
        if not os.path.isfile(cnmts_file):
            logger.warning(f"TitleDB file {cnmts_file} does not exist. TitleDB files need to be downloaded first.")
            return False

        region_titles_file = os.path.join(TITLEDB_DIR, titledb.get_region_titles_file(app_settings))
        if not os.path.isfile(region_titles_file):
            logger.warning(f"TitleDB file {region_titles_file} does not exist. TitleDB files need to be downloaded first.")
            return False

        versions_file = os.path.join(TITLEDB_DIR, 'versions.json')
        if not os.path.isfile(versions_file):
            logger.warning(f"TitleDB file {versions_file} does not exist. TitleDB files need to be downloaded first.")
            return False

        versions_txt_file = os.path.join(TITLEDB_DIR, 'versions.txt')
        if not os.path.isfile(versions_txt_file):
            logger.warning(f"TitleDB file {versions_txt_file} does not exist. TitleDB files need to be downloaded first.")
            return False

        for attempt in range(2):
            try:
                _cnmts_db = _load_json_file(cnmts_file, 'cnmts')
                _titles_db = _load_json_file(region_titles_file, 'region_titles')

                # Build an O(1) lookup by title id once to avoid repeated full scans.
                by_title_id = {}
                if isinstance(_titles_db, dict):
                    for item in _titles_db.values():
                        if not isinstance(item, dict):
                            continue
                        tid = (item.get('id') or '').strip().upper()
                        if tid:
                            by_title_id[tid] = item
                _titles_by_title_id = by_title_id
                # Keep only the direct lookup map to avoid retaining a second large dict.
                _titles_db = None

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

                _versions_db = _load_json_file(versions_file, 'versions')

                _versions_txt_db = {}
                with open(versions_txt_file, encoding="utf-8") as f:
                    for line in f:
                        line_strip = line.rstrip("\n")
                        app_id, _, version = line_strip.split('|')
                        if not version:
                            version = "0"
                        _versions_txt_db[app_id] = version

                _titles_db_loaded = True
                identification_in_progress_count += 1
                logger.info("TitleDBs loaded.")
                return True
            except CorruptedTitleDBFileError as e:
                _reset_titledb_state()
                if attempt == 0:
                    _recover_corrupted_titledb_file(app_settings, e.file_path, e.label)
                    continue
                logger.error(f"Failed to load TitleDB files after recovery attempt: {e}")
                raise
            except Exception as e:
                _reset_titledb_state()
                logger.error(f"Failed to load TitleDB files: {e}")
                raise

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
            'refcount': int(identification_in_progress_count or 0),
            'sizes': {
                'cnmts': len(_cnmts_db) if isinstance(_cnmts_db, dict) else 0,
                'titles_by_title_id': len(_titles_by_title_id) if isinstance(_titles_by_title_id, dict) else 0,
                'titles_desc_by_title_id': len(_titles_desc_by_title_id) if isinstance(_titles_desc_by_title_id, dict) else 0,
                'titles_images_by_title_id': len(_titles_images_by_title_id) if isinstance(_titles_images_by_title_id, dict) else 0,
                'versions': len(_versions_db) if isinstance(_versions_db, dict) else 0,
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
        _titles_desc_db = None
        _titles_desc_by_title_id = None
        _titles_images_by_title_id = None
        _titles_db_loaded = False
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

def get_game_info(title_id):
    global _titles_db
    global _titles_by_title_id
    global _titles_desc_by_title_id
    global _titles_images_by_title_id
    if _titles_db is None and _titles_by_title_id is None:
        logger.warning("titles_db is not loaded. Call load_titledb first.")
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
        title_info = (_titles_by_title_id or {}).get(title_key)
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
        logger.error(f"Title ID not found in titledb: {title_id}")
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
    if _titles_db is None and _titles_by_title_id is None:
        logger.warning("titles_db is not loaded. Call load_titledb first.")
        return []

    def _normalize_search_text(value):
        text = str(value or '')
        try:
            text = unicodedata.normalize('NFKD', text)
            text = text.encode('ascii', 'ignore').decode('ascii')
        except Exception:
            pass
        text = re.sub(r"[^A-Za-z0-9\s]+", " ", text)
        return re.sub(r"\s+", " ", text).strip().lower()

    q = _normalize_search_text(query)
    if not q:
        return []

    try:
        limit = int(limit)
    except Exception:
        limit = 20
    limit = max(1, min(limit, 100))

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

        hay = _normalize_search_text(f"{tid} {name}")
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
    global _versions_db
    if _versions_db is None:
        logger.warning("versions_db is not loaded. Call load_titledb first.")
        return []

    if not titleid:
        logger.warning("get_all_existing_versions called with None or empty titleid")
        return []

    titleid = titleid.lower()
    if titleid not in _versions_db:
        # print(f'Title ID not in versions.json: {titleid.upper()}')
        return []

    versions_from_db = _versions_db[titleid].keys()
    return [
        {
            'version': int(version_from_db),
            'update_number': get_update_number(version_from_db),
            'release_date': _versions_db[titleid][str(version_from_db)],
        }
        for version_from_db in versions_from_db
    ]

def get_all_app_existing_versions(app_id):
    global _cnmts_db
    if _cnmts_db is None:
        logger.warning("cnmts_db is not loaded. Call load_titledb first.")
        return None

    if not app_id:
        logger.warning("get_all_app_existing_versions called with None or empty app_id")
        return None

    app_id = app_id.lower()
    if app_id in _cnmts_db:
        versions_from_cnmts_db = _cnmts_db[app_id].keys()
        if len(versions_from_cnmts_db):
            return sorted(versions_from_cnmts_db)
        else:
            logger.warning(f'No keys in cnmts.json for app ID: {app_id.upper()}')
            return None
    else:
        # print(f'DLC app ID not in cnmts.json: {app_id.upper()}')
        return None
    
def get_app_id_version_from_versions_txt(app_id):
    global _versions_txt_db
    if _versions_txt_db is None:
        logger.warning("versions_txt_db is not loaded. Call load_titledb first.")
        return None
    if not app_id:
        logger.warning("get_app_id_version_from_versions_txt called with None or empty app_id")
        return None
    return _versions_txt_db.get(app_id, None)
    
def get_all_existing_dlc(title_id):
    global _cnmts_db
    if _cnmts_db is None:
        logger.warning("cnmts_db is not loaded. Call load_titledb first.")
        return []

    if not title_id:
        logger.warning("get_all_existing_dlc called with None or empty title_id")
        return []

    title_id = title_id.lower()
    dlcs = []
    for app_id in _cnmts_db.keys():
        for version, version_description in _cnmts_db[app_id].items():
            if version_description.get('titleType') == 130 and version_description.get('otherApplicationId') == title_id:
                if app_id.upper() not in dlcs:
                    dlcs.append(app_id.upper())
    return dlcs
