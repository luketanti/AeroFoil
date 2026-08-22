from app.constants import *
import yaml
import os
from urllib.parse import urlparse
import time
import hashlib
import threading
from Crypto.PublicKey import RSA

import logging

# Retrieve main logger
logger = logging.getLogger('main')

# Cache for settings
_settings_cache = None
_settings_cache_time = 0
_settings_cache_ttl = 5  # Cache for 5 seconds
_settings_cache_signature = None
_settings_cache_lock = threading.Lock()

# Cache key validation results by absolute path + file checksum to avoid
# re-running nsz Keys.load() on every settings refresh.
_keys_validation_cache = {}
_keys_validation_lock = threading.Lock()
_keys_validation_cache_max = 16
_DOCKER_CONVERSION_STAGING_DIR = '/app/conversion-tmp'


def _get_config_signature():
    try:
        stat = os.stat(CONFIG_FILE)
        return (int(stat.st_mtime_ns), int(stat.st_size))
    except OSError:
        return None


def _get_keys_signature():
    try:
        stat = os.stat(KEYS_FILE)
        return (int(stat.st_mtime_ns), int(stat.st_size))
    except OSError:
        return None


def _get_settings_signature():
    return (_get_config_signature(), _get_keys_signature())


def _is_settings_cache_valid(current_signature, current_time):
    if _settings_cache is None:
        return False
    if _settings_cache_signature is not None and current_signature == _settings_cache_signature:
        return True
    if current_signature is None and (current_time - _settings_cache_time) < _settings_cache_ttl:
        return True
    return False


def _invalidate_settings_cache():
    global _settings_cache, _settings_cache_time, _settings_cache_signature
    _settings_cache = None
    _settings_cache_time = 0
    _settings_cache_signature = None


def _hash_file_sha256(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 64), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def _collect_keys_revisions(keys_module):
    incorrect = []
    loaded = []
    try:
        getter = getattr(keys_module, 'getIncorrectKeysRevisions', None)
        if callable(getter):
            incorrect = list(getter() or [])
    except Exception:
        incorrect = []
    try:
        getter = getattr(keys_module, 'getLoadedKeysRevisions', None)
        if callable(getter):
            loaded = list(getter() or [])
    except Exception:
        loaded = []
    return loaded, incorrect


def _resolve_keys_validation_result(valid_flag, loaded_revisions, incorrect_revisions, log_warnings=True):
    valid = bool(valid_flag)
    loaded = list(loaded_revisions or [])
    incorrect = list(incorrect_revisions or [])
    if valid:
        return True, []
    if loaded:
        if log_warnings:
            logger.warning(
                "Keys loaded with warnings. Loaded revisions: %s, incorrect revisions: %s",
                loaded,
                incorrect,
            )
        return True, []
    errors = []
    if incorrect:
        errors.extend([f"incorrect_{rev}" for rev in incorrect])
    if not errors:
        errors.append('no_valid_master_keys')
    return False, errors


def _cache_keys_validation_result(cache_key, value):
    _keys_validation_cache[cache_key] = value
    while len(_keys_validation_cache) > _keys_validation_cache_max:
        _keys_validation_cache.pop(next(iter(_keys_validation_cache)))

def _normalize_titles_manual_overrides(raw_overrides):
    if not isinstance(raw_overrides, dict):
        return {}

    out = {}
    for key, value in raw_overrides.items():
        title_id = str(key or '').strip().upper()
        if not title_id:
            continue
        if not isinstance(value, dict):
            continue
        screenshots = value.get('screenshots') or []
        if not isinstance(screenshots, list):
            screenshots = []
        screenshots = [str(u).strip() for u in screenshots if str(u or '').strip()]
        out[title_id] = {
            'name': str(value.get('name') or '').strip(),
            'description': str(value.get('description') or '').strip(),
            'iconUrl': str(value.get('iconUrl') or '').strip(),
            'bannerUrl': str(value.get('bannerUrl') or '').strip(),
            'category': str(value.get('category') or '').strip(),
            'nsuId': str(value.get('nsuId') or '').strip(),
            'rating': str(value.get('rating') or '').strip(),
            'screenshots': screenshots[:12],
        }
    return out


def _get_built_in_titles_manual_overrides():
    return _normalize_titles_manual_overrides(BUILTIN_TITLE_MANUAL_OVERRIDES)


def _merge_titles_manual_overrides(raw_overrides):
    merged = _get_built_in_titles_manual_overrides()
    merged.update(_normalize_titles_manual_overrides(raw_overrides))
    return merged


def _normalize_titles_settings(raw_titles):
    defaults = DEFAULT_SETTINGS.get('titles', {}) or {}
    merged = defaults.copy()
    if isinstance(raw_titles, dict):
        merged.update(raw_titles)

    region = str(merged.get('region') or defaults.get('region') or 'US').strip()
    language = str(merged.get('language') or defaults.get('language') or 'en').strip()
    merged['region'] = region or 'US'
    merged['language'] = language or 'en'
    merged['prefer_english_metadata'] = _coerce_bool(
        merged.get('prefer_english_metadata'),
        default=defaults.get('prefer_english_metadata', False),
    )
    user_overrides = _normalize_titles_manual_overrides(merged.get('manual_overrides'))
    merged['manual_overrides'] = user_overrides
    merged['effective_manual_overrides'] = _merge_titles_manual_overrides(user_overrides)
    return merged

def _normalize_library_naming_templates(raw_templates):
    default_templates = (
        DEFAULT_SETTINGS.get('library', {})
        .get('naming_templates', {})
        .get('templates', {})
    )
    default_active = (
        DEFAULT_SETTINGS.get('library', {})
        .get('naming_templates', {})
        .get('active', 'default')
    )

    templates = {}
    if isinstance(raw_templates, dict):
        templates = raw_templates.get('templates', {}) or {}
        active = raw_templates.get('active') or default_active
    else:
        active = default_active

    if not isinstance(templates, dict) or not templates:
        templates = default_templates
        active = default_active

    normalized = {}
    for name, cfg in templates.items():
        if not isinstance(cfg, dict):
            continue
        clean = {}
        for section in ('base', 'update', 'dlc', 'other'):
            sec = cfg.get(section) or {}
            if not isinstance(sec, dict):
                sec = {}
            fallback = (default_templates.get('default') or {}).get(section, {})
            clean[section] = {
                'folder': str(sec.get('folder') or fallback.get('folder') or ''),
                'filename': str(sec.get('filename') or fallback.get('filename') or ''),
            }
        legacy_update_filename = clean.get('update', {}).get('filename')
        if legacy_update_filename == "{title} [{title_id}] [UPDATE][v{version}].{ext}":
            clean['update']['filename'] = "{title} [{app_id}] [UPDATE][v{version}].{ext}"
        clean_name = str(name or '').strip() or 'default'
        normalized[clean_name] = clean

    if not normalized:
        normalized = default_templates
        active = default_active

    if active not in normalized:
        active = next(iter(normalized.keys()))

    return {
        'active': active,
        'templates': normalized,
    }

def _normalize_conversion_staging_dir(raw_path):
    text = str(raw_path or '').strip()
    if not text:
        return ''
    return os.path.abspath(os.path.expanduser(text))


def _normalize_download_search_char_replacements(raw_rules):
    default_rules = (
        DEFAULT_SETTINGS.get('downloads', {})
        .get('search_char_replacements', [])
    )
    rules_source = raw_rules if isinstance(raw_rules, list) else default_rules
    normalized = []
    seen_from = set()
    for entry in rules_source:
        if isinstance(entry, dict):
            from_text = str(entry.get('from') or '')
            to_text = str(entry.get('to') or '')
        elif isinstance(entry, str):
            from_text = entry
            to_text = ''
        else:
            continue
        if not from_text:
            continue
        if from_text in seen_from:
            continue
        normalized.append({'from': from_text, 'to': to_text})
        seen_from.add(from_text)
    return normalized


def _normalize_download_client_config(raw_client, defaults, allow_credentials=True, allow_download_path=True, allow_api_key=False, shared_category=None):
    merged = (defaults or {}).copy()
    if isinstance(raw_client, dict):
        merged.update(raw_client)

    raw_category = ''
    if isinstance(raw_client, dict):
        raw_category = str(raw_client.get('category') or '').strip()
    resolved_category = str(
        raw_category
        or shared_category
        or defaults.get('category')
        or 'aerofoil'
    ).strip()
    normalized = {
        'type': str(merged.get('type') or defaults.get('type') or '').strip().lower(),
        'url': str(merged.get('url') or '').strip(),
        'category': resolved_category,
    }
    if allow_credentials:
        normalized['username'] = str(merged.get('username') or '').strip()
        normalized['password'] = str(merged.get('password') or '')
    if allow_download_path:
        normalized['download_path'] = str(merged.get('download_path') or '').strip()
    if allow_api_key:
        normalized['api_key'] = str(merged.get('api_key') or '').strip()
    return normalized


def _normalize_download_settings(downloads):
    defaults = DEFAULT_SETTINGS.get('downloads', {}) or {}
    raw_downloads = downloads if isinstance(downloads, dict) else {}
    merged = defaults.copy()
    merged.update(raw_downloads)
    required_terms_match = str(merged.get('required_terms_match') or 'all').strip().lower()
    merged['required_terms_match'] = required_terms_match if required_terms_match in ('all', 'any') else 'all'
    legacy_min_seeders = raw_downloads.get('min_seeders')
    shared_category = str(
        merged.get('category')
        or (merged.get('torrent_client') or {}).get('category')
        or (merged.get('usenet_client') or {}).get('category')
        or defaults.get('category')
        or 'aerofoil'
    ).strip()
    merged['category'] = shared_category

    prowlarr_defaults = defaults.get('prowlarr', {})
    merged_prowlarr = prowlarr_defaults.copy()
    merged_prowlarr.update(merged.get('prowlarr') or {})
    merged['prowlarr'] = merged_prowlarr
    merged['search_char_replacements'] = _normalize_download_search_char_replacements(
        merged.get('search_char_replacements')
    )
    raw_torrent_client = dict(raw_downloads.get('torrent_client') or {})
    if 'min_seeders' not in raw_torrent_client and legacy_min_seeders is not None:
        raw_torrent_client['min_seeders'] = legacy_min_seeders
    merged['torrent_client'] = _normalize_download_client_config(
        raw_torrent_client,
        defaults.get('torrent_client', {}),
        allow_credentials=True,
        allow_download_path=True,
        allow_api_key=False,
        shared_category=shared_category,
    )
    merged['torrent_client']['min_seeders'] = _coerce_int(
        raw_torrent_client.get('min_seeders'),
        default=(defaults.get('torrent_client', {}) or {}).get('min_seeders', 2),
        minimum=0,
        maximum=100000,
    )
    merged['torrent_client']['remove_completed_torrents_on_finish'] = _coerce_bool(
        raw_torrent_client.get('remove_completed_torrents_on_finish'),
        default=(defaults.get('torrent_client', {}) or {}).get('remove_completed_torrents_on_finish', True),
    )
    raw_usenet_client = dict(raw_downloads.get('usenet_client') or {})
    merged['usenet_client'] = _normalize_download_client_config(
        raw_usenet_client,
        defaults.get('usenet_client', {}),
        allow_credentials=True,
        allow_download_path=False,
        allow_api_key=True,
        shared_category=shared_category,
    )
    merged['usenet_client']['min_age_minutes'] = _coerce_int(
        raw_usenet_client.get('min_age_minutes'),
        default=(defaults.get('usenet_client', {}) or {}).get('min_age_minutes', 0),
        minimum=0,
        maximum=10000000,
    )
    merged.pop('min_seeders', None)
    return merged

def _read_env_bool(key):
    raw = os.environ.get(key)
    if raw is None:
        return None
    lowered = str(raw).strip().lower()
    if lowered in ('1', 'true', 'yes', 'on'):
        return True
    if lowered in ('0', 'false', 'no', 'off'):
        return False
    return None


def _read_env_csv(key):
    raw = os.environ.get(key)
    if raw is None:
        return None
    raw = str(raw).strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(',') if item.strip()]

def _resolve_env_conversion_staging_dir():
    enabled = _read_env_bool('AEROFOIL_CONVERSION_STAGING_ENABLED')
    if enabled is None:
        enabled = _read_env_bool('OWNFOIL_CONVERSION_STAGING_ENABLED')

    env_dir = os.environ.get('AEROFOIL_CONVERSION_STAGING_DIR')
    if env_dir is None:
        env_dir = os.environ.get('OWNFOIL_CONVERSION_STAGING_DIR')

    if enabled is False:
        return ''
    if env_dir is not None:
        return env_dir
    if enabled is True:
        return _DOCKER_CONVERSION_STAGING_DIR
    return None

def _coerce_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ('1', 'true', 'yes', 'on'):
            return True
        if lowered in ('0', 'false', 'no', 'off'):
            return False
    return bool(default)

def _coerce_int(value, default=0, minimum=None, maximum=None):
    try:
        out = int(value)
    except Exception:
        out = int(default)
    if minimum is not None:
        out = max(int(minimum), out)
    if maximum is not None:
        out = min(int(maximum), out)
    return out

def _normalize_ip_entries(raw):
    if raw is None:
        return []

    entries = []
    if isinstance(raw, str):
        entries = [raw]
    elif isinstance(raw, (list, tuple, set)):
        entries = list(raw)

    out = []
    seen = set()
    for item in entries:
        text = str(item or '').strip()
        if not text:
            continue
        # Accept comma and newline separated input.
        for segment in text.replace('\r', '\n').replace(',', '\n').split('\n'):
            candidate = str(segment or '').strip()
            if not candidate:
                continue
            key = candidate.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(candidate)
    return out

def _normalize_country_codes(raw):
    if raw is None:
        return []

    entries = []
    if isinstance(raw, str):
        entries = [raw]
    elif isinstance(raw, (list, tuple, set)):
        entries = list(raw)

    out = []
    seen = set()
    for item in entries:
        text = str(item or '').strip()
        if not text:
            continue
        for segment in text.replace('\r', '\n').replace(',', '\n').split('\n'):
            candidate = str(segment or '').strip().upper()
            if not candidate:
                continue
            if len(candidate) != 2 or not candidate.isalpha():
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            out.append(candidate)
    return out

def _normalize_security_settings(raw_security):
    defaults = DEFAULT_SETTINGS.get('security', {}) or {}
    merged = defaults.copy()
    if isinstance(raw_security, dict):
        merged.update(raw_security)

    merged['trust_proxy_headers'] = _coerce_bool(
        merged.get('trust_proxy_headers'),
        default=defaults.get('trust_proxy_headers', False),
    )
    merged['trusted_proxies'] = _normalize_ip_entries(merged.get('trusted_proxies'))
    merged['auth_ip_lockout_enabled'] = _coerce_bool(
        merged.get('auth_ip_lockout_enabled'),
        default=defaults.get('auth_ip_lockout_enabled', True),
    )
    merged['auth_ip_lockout_threshold'] = _coerce_int(
        merged.get('auth_ip_lockout_threshold'),
        default=defaults.get('auth_ip_lockout_threshold', 5),
        minimum=1,
        maximum=1000,
    )
    merged['auth_ip_lockout_window_seconds'] = _coerce_int(
        merged.get('auth_ip_lockout_window_seconds'),
        default=defaults.get('auth_ip_lockout_window_seconds', 600),
        minimum=10,
        maximum=86400,
    )
    merged['auth_ip_lockout_duration_seconds'] = _coerce_int(
        merged.get('auth_ip_lockout_duration_seconds'),
        default=defaults.get('auth_ip_lockout_duration_seconds', 1800),
        minimum=10,
        maximum=604800,
    )
    merged['auth_permanent_ip_blacklist'] = _normalize_ip_entries(
        merged.get('auth_permanent_ip_blacklist')
    )
    merged['auth_blocked_country_codes'] = _normalize_country_codes(
        merged.get('auth_blocked_country_codes')
    )
    merged['auth_allowed_country_codes'] = _normalize_country_codes(
        merged.get('auth_allowed_country_codes')
    )
    return merged


def _normalize_shop_settings(raw_shop):
    defaults = DEFAULT_SETTINGS.get('shop', {}) or {}
    merged = defaults.copy()
    if isinstance(raw_shop, dict):
        merged.update(raw_shop)

    merged['motd_enabled'] = _coerce_bool(
        merged.get('motd_enabled'),
        default=defaults.get('motd_enabled', True),
    )
    merged['motd'] = str(merged.get('motd') or defaults.get('motd') or '').strip()
    merged['motd_api_url'] = str(merged.get('motd_api_url') or defaults.get('motd_api_url') or '').strip()
    merged['public'] = _coerce_bool(
        merged.get('public'),
        default=defaults.get('public', False),
    )
    merged['external_tinfoil_only'] = _coerce_bool(
        merged.get('external_tinfoil_only'),
        default=defaults.get('external_tinfoil_only', False),
    )
    merged['encrypt'] = _coerce_bool(
        merged.get('encrypt'),
        default=defaults.get('encrypt', True),
    )
    merged['fast_transfer_mode'] = _coerce_bool(
        merged.get('fast_transfer_mode'),
        default=defaults.get('fast_transfer_mode', False),
    )
    merged['cyberfoil_virtual_compressed_stream'] = _coerce_bool(
        merged.get('cyberfoil_virtual_compressed_stream'),
        default=defaults.get('cyberfoil_virtual_compressed_stream', True),
    )
    merged['tinfoil_only_mode'] = _coerce_bool(
        merged.get('tinfoil_only_mode'),
        default=defaults.get('tinfoil_only_mode', False),
    )
    merged['public_key'] = str(merged.get('public_key') or '').strip()
    merged['clientCertPub'] = str(merged.get('clientCertPub') or defaults.get('clientCertPub') or '').strip()
    merged['clientCertKey'] = str(merged.get('clientCertKey') or defaults.get('clientCertKey') or '').strip()
    merged['host'] = str(merged.get('host') or '').strip()
    merged['hauth'] = str(merged.get('hauth') or '').strip()

    if merged['tinfoil_only_mode']:
        merged['encrypt'] = True

    return merged


def _normalize_content_filter_settings(raw_content_filter):
    defaults = DEFAULT_SETTINGS.get('content_filter', {}) or {}
    merged = defaults.copy()
    if isinstance(raw_content_filter, dict):
        merged.update(raw_content_filter)
    merged['block_unrated'] = _coerce_bool(
        merged.get('block_unrated'),
        default=defaults.get('block_unrated', True),
    )
    return merged


def _normalize_cheats_settings(raw_cheats):
    defaults = DEFAULT_SETTINGS.get('cheats', {}) or {}
    merged = defaults.copy()
    if isinstance(raw_cheats, dict):
        merged.update(raw_cheats)
    merged['enabled'] = _coerce_bool(merged.get('enabled'), default=defaults.get('enabled', True))
    merged['sync_url'] = str(merged.get('sync_url') or '').strip()
    return merged


def _validate_shop_public_key(public_key_pem):
    key_text = str(public_key_pem or '').strip()
    if not key_text:
        return True, None
    try:
        key = RSA.import_key(key_text)
    except Exception as exc:
        return False, f'Invalid public key: {exc}'
    if getattr(key, 'has_private', lambda: False)():
        return False, 'Invalid public key: expected a public key, not a private key.'
    return True, None


def _validate_shop_motd_api_url(value):
    raw = str(value or '').strip()
    if not raw:
        return True, None
    if len(raw) > 2048:
        return False, 'MOTD API URL is too long.'
    try:
        parsed = urlparse(raw)
    except Exception:
        return False, 'Invalid MOTD API URL.'
    scheme = str(parsed.scheme or '').lower()
    if scheme not in ('http', 'https'):
        return False, 'MOTD API URL must use http or https.'
    if not parsed.netloc:
        return False, 'MOTD API URL must include a host.'
    return True, None

def load_keys(key_file=KEYS_FILE):
    try:
        file_path = os.path.abspath(str(key_file or KEYS_FILE))
    except Exception:
        file_path = os.path.abspath(str(KEYS_FILE))
    if not os.path.isfile(file_path):
        return False
    valid, _ = validate_keys_file(file_path)
    return valid


def validate_keys_file(key_file=KEYS_FILE):
    """
    Validate a keys file and return (is_valid, errors).
    Accept partially-valid key sets when at least one master key revision
    was loaded, which is sufficient for many metadata operations.
    """
    valid = False
    errors = []
    file_path = os.path.abspath(str(key_file or KEYS_FILE))
    if not os.path.isfile(file_path):
        logger.debug(f'Keys file {key_file} does not exist.')
        return valid, []

    try:
        checksum = _hash_file_sha256(file_path)
    except Exception as e:
        logger.error(f'Failed to hash keys file {file_path}: {e}')
        return False, [str(e)]

    cache_key = (file_path, checksum)
    with _keys_validation_lock:
        cached = _keys_validation_cache.get(cache_key)
        if cached is not None:
            return cached

    try:
        from nsz.nut import Keys
    except Exception as e:
        msg = f'nsz_keys_module_unavailable: {e}'
        logger.debug(msg)
        return valid, [msg]
    with _keys_validation_lock:
        cached = _keys_validation_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            loaded_checksum = None
            getter = getattr(Keys, 'getLoadedKeysChecksum', None)
            if callable(getter):
                loaded_checksum = getter()

            can_reuse_loaded_state = (
                bool(loaded_checksum)
                and str(loaded_checksum).strip().lower() == checksum.lower()
                and getattr(Keys, 'keys_loaded', None) is not None
            )

            if can_reuse_loaded_state:
                loaded, incorrect = _collect_keys_revisions(Keys)
                result = _resolve_keys_validation_result(
                    getattr(Keys, 'keys_loaded', False),
                    loaded,
                    incorrect,
                    log_warnings=False,
                )
                _cache_keys_validation_result(cache_key, result)
                return result

            valid = bool(Keys.load(file_path))
            loaded, incorrect = _collect_keys_revisions(Keys)
            result = _resolve_keys_validation_result(valid, loaded, incorrect, log_warnings=True)
            _cache_keys_validation_result(cache_key, result)
            return result
        except Exception as e:
            logger.error(f'Provided keys file {key_file} is invalid: {e}')
            return False, [str(e)]

def load_settings(force_reload=False):
    global _settings_cache, _settings_cache_time, _settings_cache_signature

    current_time = time.time()
    current_signature = _get_settings_signature()

    if not force_reload and _is_settings_cache_valid(current_signature, current_time):
        return _settings_cache

    with _settings_cache_lock:
        current_time = time.time()
        current_signature = _get_settings_signature()
        if not force_reload and _is_settings_cache_valid(current_signature, current_time):
            return _settings_cache

        config_exists = os.path.exists(CONFIG_FILE)
        if config_exists:
            logger.debug('Reading configuration file.')
            with open(CONFIG_FILE, 'r') as yaml_file:
                settings = yaml.safe_load(yaml_file) or {}
            if not isinstance(settings, dict):
                settings = {}
        else:
            settings = {}

        def _merge_section(name):
            defaults = DEFAULT_SETTINGS.get(name, {})
            merged = defaults.copy()
            raw_section = settings.get(name, {})
            if isinstance(raw_section, dict):
                merged.update(raw_section)
            settings[name] = merged

        _merge_section('security')
        _merge_section('shop')
        _merge_section('titles')
        _merge_section('library')
        _merge_section('cheats')
        _merge_section('content_filter')

        env_trust = _read_env_bool('AEROFOIL_TRUST_PROXY_HEADERS')
        if env_trust is None:
            env_trust = _read_env_bool('OWNFOIL_TRUST_PROXY_HEADERS')
        if env_trust is not None:
            settings['security']['trust_proxy_headers'] = env_trust

        env_proxies = _read_env_csv('AEROFOIL_TRUSTED_PROXIES')
        if env_proxies is None:
            env_proxies = _read_env_csv('OWNFOIL_TRUSTED_PROXIES')
        if env_proxies is not None:
            settings['security']['trusted_proxies'] = env_proxies

        env_country_block = _read_env_csv('AEROFOIL_AUTH_BLOCKED_COUNTRY_CODES')
        if env_country_block is None:
            env_country_block = _read_env_csv('OWNFOIL_AUTH_BLOCKED_COUNTRY_CODES')
        if env_country_block is not None:
            settings['security']['auth_blocked_country_codes'] = env_country_block

        env_country_allow = _read_env_csv('AEROFOIL_AUTH_ALLOWED_COUNTRY_CODES')
        if env_country_allow is None:
            env_country_allow = _read_env_csv('OWNFOIL_AUTH_ALLOWED_COUNTRY_CODES')
        if env_country_allow is not None:
            settings['security']['auth_allowed_country_codes'] = env_country_allow

        env_conversion_staging_dir = _resolve_env_conversion_staging_dir()
        if env_conversion_staging_dir is not None:
            settings['library']['conversion_staging_dir'] = env_conversion_staging_dir

        settings['security'] = _normalize_security_settings(settings.get('security'))
        settings['downloads'] = _normalize_download_settings(settings.get('downloads'))
        settings['titles'] = _normalize_titles_settings(settings.get('titles'))
        settings['shop'] = _normalize_shop_settings(settings.get('shop'))
        settings['cheats'] = _normalize_cheats_settings(settings.get('cheats'))
        settings['content_filter'] = _normalize_content_filter_settings(settings.get('content_filter'))
        settings['library']['conversion_staging_dir'] = _normalize_conversion_staging_dir(
            settings['library'].get('conversion_staging_dir')
        )
        settings['library']['naming_templates'] = _normalize_library_naming_templates(
            settings['library'].get('naming_templates')
        )

        if not config_exists:
            with open(CONFIG_FILE, 'w') as yaml_file:
                yaml.dump(settings, yaml_file)

        settings['titles']['valid_keys'] = load_keys()

        _settings_cache = settings
        _settings_cache_time = current_time
        _settings_cache_signature = _get_settings_signature()
        return settings


def set_security_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('security', {})
    settings['security'].update(data or {})
    settings['security'] = _normalize_security_settings(settings.get('security'))
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()


def set_cheats_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('cheats', {})
    settings['cheats'].update(data or {})
    settings['cheats'] = _normalize_cheats_settings(settings.get('cheats'))
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()


def verify_settings(section, data):
    success = True
    errors = []
    if section == 'library':
        library_paths = list(data.get('paths') or [])
        validate_paths = bool(data.get('_validate_paths', True))
        if validate_paths:
            for dir in library_paths:
                if not os.path.exists(dir):
                    success = False
                    errors.append({
                        'path': 'library/path',
                        'error': f"Path {dir} does not exists."
                    })
                    break
        raw_conversion_staging_dir = str(data.get('conversion_staging_dir') or '').strip()
        conversion_staging_dir = _normalize_conversion_staging_dir(raw_conversion_staging_dir)
        if conversion_staging_dir:
            if not os.path.isabs(raw_conversion_staging_dir):
                success = False
                errors.append({
                    'path': 'library/conversion_staging_dir',
                    'error': 'Conversion staging directory must be an absolute path.'
                })
            elif not os.path.isdir(conversion_staging_dir):
                success = False
                errors.append({
                    'path': 'library/conversion_staging_dir',
                    'error': f"Path {conversion_staging_dir} does not exist."
                })
            elif not os.access(conversion_staging_dir, os.W_OK):
                success = False
                errors.append({
                    'path': 'library/conversion_staging_dir',
                    'error': f"Path {conversion_staging_dir} is not writable."
                })
            else:
                for library_path in library_paths:
                    abs_library_path = os.path.abspath(os.path.expanduser(str(library_path or '').strip()))
                    if not abs_library_path:
                        continue
                    try:
                        common = os.path.commonpath([conversion_staging_dir, abs_library_path])
                    except ValueError:
                        continue
                    if common == abs_library_path:
                        success = False
                        errors.append({
                            'path': 'library/conversion_staging_dir',
                            'error': 'Conversion staging directory must not be inside a configured library path.'
                        })
                        break
    elif section == 'shop':
        normalized = _normalize_shop_settings(data)
        public_key_ok, public_key_error = _validate_shop_public_key(normalized.get('public_key'))
        if not public_key_ok:
            success = False
            errors.append({
                'path': 'shop/public_key',
                'error': public_key_error,
            })
        motd_api_ok, motd_api_error = _validate_shop_motd_api_url(normalized.get('motd_api_url'))
        if not motd_api_ok:
            success = False
            errors.append({
                'path': 'shop/motd_api_url',
                'error': motd_api_error,
            })
    return success, errors

def add_library_path_to_settings(path):
    success = True
    errors = []
    if not os.path.exists(path):
        success = False
        errors.append({
            'path': 'library/paths',
            'error': f"Path {path} does not exists."
        })
        return success, errors

    settings = load_settings(force_reload=True)
    library_paths = settings['library']['paths']
    if library_paths:
        if path in library_paths:
            success = False
            errors.append({
                'path': 'library/paths',
                'error': f"Path {path} already configured."
            })
            return success, errors
        library_paths.append(path)
    else:
        library_paths = [path]
    settings['library']['paths'] = library_paths
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()
    return success, errors

def delete_library_path_from_settings(path):
    success = True
    errors = []
    settings = load_settings(force_reload=True)
    library_paths = settings['library']['paths']
    if library_paths:
        if path in library_paths:
            library_paths.remove(path)
            settings['library']['paths'] = library_paths
            with open(CONFIG_FILE, 'w') as yaml_file:
                yaml.dump(settings, yaml_file)
            _invalidate_settings_cache()
        else:
            success = False
            errors.append({
                    'path': 'library/paths',
                    'error': f"Path {path} not configured."
                })
    return success, errors

def set_titles_settings(region, language, prefer_english_metadata=False):
    settings = load_settings(force_reload=True)
    settings.setdefault('titles', {})
    settings['titles'].update({
        'region': region,
        'language': language,
        'prefer_english_metadata': prefer_english_metadata,
    })
    settings['titles'] = _normalize_titles_settings(settings.get('titles'))
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()

def set_manual_title_override(title_id, data):
    title_id = str(title_id or '').strip().upper()
    if not title_id:
        return False

    settings = load_settings(force_reload=True)
    settings.setdefault('titles', {})
    overrides = _normalize_titles_manual_overrides(settings['titles'].get('manual_overrides'))
    payload = _normalize_titles_manual_overrides({title_id: data}).get(title_id)
    if not payload:
        return False

    has_value = any([
        payload.get('name'),
        payload.get('description'),
        payload.get('iconUrl'),
        payload.get('bannerUrl'),
        payload.get('category'),
        payload.get('nsuId'),
        payload.get('rating'),
        bool(payload.get('screenshots')),
    ])
    if has_value:
        overrides[title_id] = payload
    else:
        overrides.pop(title_id, None)

    settings['titles']['manual_overrides'] = overrides
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()
    return True

def set_shop_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('shop', {})
    shop_host = data['host']
    if '://' in shop_host:
        data['host'] = shop_host.split('://')[-1]
    settings['shop'].update(data)
    settings['shop'] = _normalize_shop_settings(settings.get('shop'))
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()

def set_content_filter_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('content_filter', {})
    settings['content_filter'].update(data or {})
    settings['content_filter'] = _normalize_content_filter_settings(settings.get('content_filter'))
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()


def set_download_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('downloads', {})
    incoming = dict(data or {})
    if 'search_char_replacements' in incoming:
        incoming['search_char_replacements'] = _normalize_download_search_char_replacements(
            incoming.get('search_char_replacements')
        )
    current = settings.get('downloads', {})
    merged = dict(current)
    merged.update(incoming)
    settings['downloads'] = _normalize_download_settings(merged)
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()


def set_library_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('library', {})
    if data and 'naming_templates' in data:
        data['naming_templates'] = _normalize_library_naming_templates(data.get('naming_templates'))
    if data and 'conversion_staging_dir' in data:
        data['conversion_staging_dir'] = _normalize_conversion_staging_dir(
            data.get('conversion_staging_dir')
        )
    settings['library'].update(data)
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    _invalidate_settings_cache()
