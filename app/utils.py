import logging
import re
import threading
from functools import wraps
import json
import os
import tempfile
import time
import logging
import subprocess
import ipaddress
import requests

_geoip_lock = threading.Lock()
_geoip_db = None
_geoip_db_error = None
_geoip_last_check = 0.0
_geoip_ttl_s = 900
_geoip_download_lock = threading.Lock()
_geoip_download_inflight = False

# Global lock for all JSON writes in this process
_json_write_lock = threading.Lock()
_version_cache = None
_version_cache_time = 0
_version_cache_ttl = 30

# Custom logging formatter to support colors
class ColoredFormatter(logging.Formatter):
    # Define color codes
    COLORS = {
        'DEBUG': '\033[94m',   # Blue
        'INFO': '\033[92m',    # Green
        'WARNING': '\033[93m', # Yellow
        'ERROR': '\033[91m',   # Red
        'CRITICAL': '\033[95m' # Magenta
    }
    RESET = '\033[0m'  # Reset color

    def format(self, record):
        # Add color to the log level name
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        
        return super().format(record)
    
# Filter to remove date from http access logs
class FilterRemoveDateFromWerkzeugLogs(logging.Filter):
    # '192.168.0.102 - - [30/Jun/2024 01:14:03] "%s" %s %s' -> '192.168.0.102 - "%s" %s %s'
    pattern: re.Pattern = re.compile(r' - - \[.+?] "')

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.pattern.sub(' - "', record.msg)
        return True


def debounce(wait):
    """Decorator that postpones a function's execution until after `wait` seconds
    have elapsed since the last time it was invoked."""
    def decorator(fn):
        lock = threading.Lock()
        condition = threading.Condition(lock)
        state = {
            "deadline": None,
            "args": None,
            "kwargs": None,
            "running": False,
            "stop": False,
        }

        def runner():
            while True:
                with condition:
                    while state["deadline"] is None and not state["stop"]:
                        condition.wait()
                    if state["stop"]:
                        return

                    while True:
                        remaining = state["deadline"] - time.time()
                        if remaining <= 0:
                            break
                        condition.wait(timeout=remaining)
                        if state["deadline"] is None or state["stop"]:
                            break

                    if state["stop"]:
                        return

                    if state["deadline"] is None:
                        continue

                    args = state["args"]
                    kwargs = state["kwargs"]
                    state["deadline"] = None

                fn(*args, **kwargs)

        @wraps(fn)
        def debounced(*args, **kwargs):
            with condition:
                state["args"] = args
                state["kwargs"] = kwargs
                state["deadline"] = time.time() + wait
                if not state["running"]:
                    state["running"] = True
                    thread = threading.Thread(target=runner, daemon=True)
                    thread.start()
                condition.notify()

        def cancel():
            with condition:
                state["deadline"] = None
                condition.notify()

        debounced.cancel = cancel
        return debounced
    return decorator

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ['keys', 'txt']

def safe_write_json(path, data, **dump_kwargs):
    with _json_write_lock:
        dirpath = os.path.dirname(path) or "."
        # Create temporary file in same directory
        with tempfile.NamedTemporaryFile("w", dir=dirpath, delete=False, encoding="utf-8") as tmp:
            tmp_path = tmp.name
            json.dump(data, tmp, ensure_ascii=False, indent=2, **dump_kwargs)
            tmp.flush()
            os.fsync(tmp.fileno())  # flush to disk
        # Atomically replace target file
        os.replace(tmp_path, path)

def get_app_version(fallback=None):
    global _version_cache, _version_cache_time
    now = time.time()
    if _version_cache and (now - _version_cache_time) < _version_cache_ttl:
        return _version_cache

    env_version = os.environ.get('AEROFOIL_VERSION') or os.environ.get('OWNFOIL_VERSION') or os.environ.get('APP_VERSION')
    if env_version:
        _version_cache = env_version.strip()
        _version_cache_time = now
        return _version_cache

    version = None
    try:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result = subprocess.run(
            ['git', 'describe', '--tags', '--dirty', '--always'],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
            check=False,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
    except Exception:
        version = None

    if version and version.endswith('-dirty'):
        version = f"{version[:-6]} (dirty)"
    if not version:
        version = (fallback or '').strip() or 'dev'

    _version_cache = version
    _version_cache_time = now
    return version


def _safe_geoip_db_path():
    try:
        from app.constants import GEOLITE_DB_FILE
        return GEOLITE_DB_FILE
    except Exception:
        return ''


def _safe_geoip_download_url():
    try:
        from app.constants import GEOLITE_DB_URL
        return GEOLITE_DB_URL
    except Exception:
        return ''


def _safe_geoip_db_dir():
    try:
        from app.constants import GEOLITE_DB_DIR
        return GEOLITE_DB_DIR
    except Exception:
        return ''


def _download_geoip_db():
    global _geoip_download_inflight
    url = _safe_geoip_download_url()
    path = _safe_geoip_db_path()
    if not url or not path:
        return
    tmp_path = f"{path}.tmp"
    try:
        db_dir = _safe_geoip_db_dir() or os.path.dirname(path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        headers = {
            'User-Agent': 'AeroFoil-GeoIP-Downloader'
        }
        with requests.get(url, timeout=30, stream=True, headers=headers) as resp:
            resp.raise_for_status()
            with open(tmp_path, 'wb') as handle:
                for chunk in resp.iter_content(chunk_size=1024 * 256):
                    if not chunk:
                        continue
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
    finally:
        with _geoip_download_lock:
            _geoip_download_inflight = False


def _schedule_geoip_download():
    global _geoip_download_inflight
    with _geoip_download_lock:
        if _geoip_download_inflight:
            return
        _geoip_download_inflight = True
    thread = threading.Thread(target=_download_geoip_db, daemon=True)
    thread.start()


def _load_geoip_db(db_path):
    global _geoip_db, _geoip_db_error
    if not db_path:
        _geoip_db_error = 'GeoIP DB path not configured.'
        return None
    try:
        import geoip2.database
    except Exception:
        _geoip_db_error = 'geoip2 not installed.'
        return None
    try:
        if not os.path.isfile(db_path):
            _geoip_db_error = f'Missing GeoIP database at {db_path}.'
            _schedule_geoip_download()
            return None
        _geoip_db = geoip2.database.Reader(db_path)
        _geoip_db_error = None
        return _geoip_db
    except Exception as e:
        _geoip_db_error = str(e)
        return None


def _normalize_geoip_ip(ip_value):
    try:
        if not ip_value:
            return ''
        ip_obj = ipaddress.ip_address(str(ip_value).strip())
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
        return str(ip_obj)
    except Exception:
        return ''


def lookup_geoip(ip_value):
    """Lookup geo data for an IP using the local GeoLite2 database."""
    global _geoip_db, _geoip_last_check
    normalized = _normalize_geoip_ip(ip_value)
    if not normalized:
        return {}

    with _geoip_lock:
        now = time.time()
        if _geoip_db is None or (now - float(_geoip_last_check)) >= _geoip_ttl_s:
            _geoip_last_check = now
            _load_geoip_db(_safe_geoip_db_path())
        reader = _geoip_db

    if reader is None:
        return {}
    try:
        record = reader.city(normalized)
    except Exception:
        return {}

    country = (record.country.names or {}).get('en') or ''
    country_code = (record.country.iso_code or '') if record.country else ''
    region = ''
    if record.subdivisions and len(record.subdivisions) > 0:
        region = (record.subdivisions[0].names or {}).get('en') or ''
    city = (record.city.names or {}).get('en') or ''
    latitude = None
    longitude = None
    try:
        latitude = float(record.location.latitude) if record.location and record.location.latitude is not None else None
        longitude = float(record.location.longitude) if record.location and record.location.longitude is not None else None
    except Exception:
        latitude = None
        longitude = None

    return {
        'country': country,
        'country_code': country_code,
        'region': region,
        'city': city,
        'latitude': latitude,
        'longitude': longitude,
    }
