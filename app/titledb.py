import unzip_http
import requests
from requests.exceptions import RequestException, ConnectionError, Timeout
import os, re
import json
import logging
import threading
import time

from app.constants import *


# Retrieve main logger
logger = logging.getLogger('main')

def get_region_titles_file(app_settings):
    return f"titles.{app_settings['titles']['region']}.{app_settings['titles']['language']}.json"

def get_preferred_english_titles_files(app_settings, available_files=None):
    titles_settings = (app_settings or {}).get('titles') or {}
    if not bool(titles_settings.get('prefer_english_metadata')):
        return []

    candidates = sorted(
        file_name
        for file_name in (available_files or [])
        if re.fullmatch(r"titles\.[A-Z]{2}\.en\.json", str(file_name or ''))
    )
    if not candidates:
        return []

    current_region = str(titles_settings.get('region') or '').strip().upper()
    preferred = []
    for file_name in (
        f"titles.{current_region}.en.json" if current_region else '',
        "titles.US.en.json",
    ):
        if file_name and file_name in candidates and file_name not in preferred:
            preferred.append(file_name)
    for file_name in candidates:
        if file_name not in preferred:
            preferred.append(file_name)
    return preferred

def download_from_remote_zip(rzf, path, store_path):
    with rzf.open(path) as fpin:
        with open(store_path, mode='wb') as fpout:
            while True:
                r = fpin.read(65536)
                if not r:
                    break
                fpout.write(r)


def is_titledb_update_available(rzf):
    update_available = False
    local_commit_file = os.path.join(TITLEDB_DIR, '.latest')
    remote_latest_commit_file = [ f.filename for f in rzf.infolist() if 'latest_' in f.filename ][0]
    latest_remote_commit = remote_latest_commit_file.split('_')[-1]

    if not os.path.isfile(local_commit_file):
        logger.info('Retrieving titledb for the first time...')
        update_available = True
    else: 
        with open(local_commit_file, 'r') as f:
            current_commit = f.read()
            
        if current_commit == latest_remote_commit:
            logger.info(f'Titledb already up to date, commit: {current_commit}')
            update_available = False
        else:
            logger.info(f'Titledb update available, current commit: {current_commit}, latest commit: {latest_remote_commit}')
            update_available = True
    
    return update_available, latest_remote_commit


def _write_latest_commit(latest_remote_commit):
    local_commit_file = os.path.join(TITLEDB_DIR, '.latest')
    with open(local_commit_file, 'w', encoding='utf-8') as f:
        f.write(str(latest_remote_commit or ''))


def _validate_downloaded_titledb_file(path, filename):
    lower_name = str(filename or '').lower()
    if lower_name.endswith('.json'):
        return _is_valid_json_file(path)
    if lower_name.endswith('.txt'):
        return os.path.isfile(path) and os.path.getsize(path) > 0
    return os.path.isfile(path)


def _remove_temp_file(path, retries=3, delay_s=0.1):
    for attempt in range(max(1, int(retries or 1))):
        try:
            if not os.path.isfile(path):
                return
            os.remove(path)
            return
        except PermissionError:
            if attempt >= max(1, int(retries or 1)) - 1:
                return
            time.sleep(delay_s)
        except Exception:
            return


def download_titledb_files(rzf, files):
    for file in files:
        store_path = os.path.join(TITLEDB_DIR, file)
        rel_store_path = os.path.relpath(store_path, start=APP_DIR)
        temp_path = f'{store_path}.tmp'
        logger.info(f'Downloading {file} from remote titledb to {rel_store_path}')
        try:
            download_from_remote_zip(rzf, file, temp_path)
            if not _validate_downloaded_titledb_file(temp_path, file):
                raise ValueError(f'Downloaded TitleDB file is invalid: {file}')
            os.replace(temp_path, store_path)
        finally:
            _remove_temp_file(temp_path)


def _get_with_retry(url, max_retries=5, backoff_factor=2, headers=None, method="GET", allow_redirects=False):
    """Get URL with retry logic for DNS and network errors."""
    # Disable requests' built-in retries to use our own retry logic
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    
    session = requests.Session()
    # Disable automatic retries - we'll handle retries ourselves
    adapter = HTTPAdapter(max_retries=0)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    for attempt in range(max_retries):
        try:
            r = session.request(method, url, allow_redirects=allow_redirects, timeout=60, headers=headers)
            return r
        except Exception as e:
            error_msg = str(e)
            error_type = type(e).__name__
            
            # Check if it's a DNS/network error
            is_dns_error = (
                'Failed to resolve' in error_msg or 
                'NameResolutionError' in error_type or
                'NameResolutionError' in error_msg or
                isinstance(e, (ConnectionError, RequestException))
            )
            
            if attempt < max_retries - 1:
                wait_time = backoff_factor ** attempt
                if is_dns_error:
                    logger.warning(f'DNS resolution failed for {url}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})...')
                elif 'Timeout' in error_type or isinstance(e, Timeout):
                    logger.warning(f'Timeout connecting to {url}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})...')
                else:
                    logger.warning(f'Network error connecting to {url}: {error_type}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})...')
                time.sleep(wait_time)
            else:
                if is_dns_error:
                    logger.error(f'DNS resolution failed for {url} after {max_retries} attempts. Check your network connection and DNS configuration.')
                else:
                    logger.error(f'Failed to connect to {url} after {max_retries} attempts: {e}')
                raise

def _is_valid_json_file(path):
    try:
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            return False
        with open(path, 'r', encoding='utf-8') as fp:
            json.load(fp)
        return True
    except Exception:
        return False

def update_titledb_files(app_settings):
    files_to_update = []
    
    region_titles_file = get_region_titles_file(app_settings)
    try:
        current_files = set(os.listdir(TITLEDB_DIR))
    except FileNotFoundError:
        current_files = set()

    try:
        r = _get_with_retry(TITLEDB_ARTEFACTS_URL, allow_redirects=False)
        if r is None:
            raise ValueError("No response received for TitleDB artefacts")
        direct_url = r.headers.get('Location') if (300 <= r.status_code < 400) else str(TITLEDB_ARTEFACTS_URL)
        rzf = unzip_http.RemoteZipFile(direct_url)
        remote_files = {info.filename for info in rzf.infolist()}
    except Exception as e:
        logger.error(f'Failed to fetch TitleDB artefacts: {e}')
        raise
    
    english_titles_files = get_preferred_english_titles_files(app_settings, available_files=remote_files)
    update_available, latest_remote_commit = is_titledb_update_available(rzf)
    if update_available:
        files_to_update = TITLEDB_DEFAULT_FILES + [region_titles_file] + english_titles_files
        old_region_titles_files = [f for f in os.listdir(TITLEDB_DIR) if re.match(r"titles\.[A-Z]{2}\.[a-z]{2}\.json", f) and f not in files_to_update]
        files_to_update += old_region_titles_files

    required_core_files = list(TITLEDB_DEFAULT_FILES) + [region_titles_file]
    missing_core_files = [file for file in required_core_files if file not in current_files]
    if missing_core_files:
        logger.warning(
            "Missing required TitleDB file(s): %s. They will be downloaded.",
            ", ".join(missing_core_files)
        )
        files_to_update.extend(missing_core_files)

    missing_english_files = [file for file in english_titles_files if file not in current_files]
    if missing_english_files:
        logger.info(
            "Missing preferred English TitleDB file(s): %s. They will be downloaded.",
            ", ".join(missing_english_files)
        )
        files_to_update.extend(missing_english_files)

    missing_optional_files = [
        file for file in TITLEDB_OPTIONAL_FILES
        if file in remote_files and file not in current_files
    ]
    if missing_optional_files:
        logger.info(
            "Missing optional TitleDB file(s): %s. They will be downloaded.",
            ", ".join(missing_optional_files)
        )
        files_to_update.extend(missing_optional_files)

    if files_to_update:
        # Keep deterministic order without duplicates.
        files_to_update = list(dict.fromkeys(files_to_update))
        download_titledb_files(rzf, files_to_update)

    if update_available:
        _write_latest_commit(latest_remote_commit)
    from app.metadata_sources import update_titledb_source_status
    update_titledb_source_status(latest_remote_commit, TITLEDB_DIR)


# Serializes concurrent runs of update_titledb (scheduled job, TitleDB
# recovery, settings save). Without it, two runs downloaded into the same
# fixed <file>.tmp paths and corrupted each other's files. A run that
# waited here typically finds everything up to date and becomes a cheap
# no-op.
_update_titledb_run_lock = threading.Lock()

def update_titledb(app_settings):
    with _update_titledb_run_lock:
        from app.metadata_sources import update_metadata_sources
        update_metadata_sources(app_settings)
        logger.info('Updating titledb...')
        if not os.path.isdir(TITLEDB_DIR):
            os.makedirs(TITLEDB_DIR, exist_ok=True)

        try:
            update_titledb_files(app_settings)
            logger.info('titledb update done.')
        except Exception as e:
            logger.error(f'TitleDB update failed: {e}')
            logger.warning('TitleDB files may be missing. Some features may not work until TitleDB is successfully downloaded.')
            raise
