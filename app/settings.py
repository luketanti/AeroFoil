from app.constants import *
import yaml
import os
import time
import hashlib
import threading

import logging

# Retrieve main logger
logger = logging.getLogger('main')

# Cache for settings
_settings_cache = None
_settings_cache_time = 0
_settings_cache_ttl = 5  # Cache for 5 seconds

# Cache key validation results by absolute path + file checksum to avoid
# re-running nsz Keys.load() on every settings refresh.
_keys_validation_cache = {}
_keys_validation_lock = threading.Lock()
_keys_validation_cache_max = 16


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
            'screenshots': screenshots[:12],
        }
    return out

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
    return merged

def load_keys(key_file=KEYS_FILE):
    valid, _ = validate_keys_file(key_file)
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
        return valid, ['keys_file_missing']

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
    global _settings_cache, _settings_cache_time
    
    current_time = time.time()
    
    # Return cached settings if still valid and not forcing reload
    if not force_reload and _settings_cache is not None and (current_time - _settings_cache_time) < _settings_cache_ttl:
        return _settings_cache
    
    if os.path.exists(CONFIG_FILE):
        logger.debug('Reading configuration file.')
        with open(CONFIG_FILE, 'r') as yaml_file:
            settings = yaml.safe_load(yaml_file)

        if 'security' not in settings:
            settings['security'] = DEFAULT_SETTINGS.get('security', {})
        else:
            defaults = DEFAULT_SETTINGS.get('security', {})
            merged = defaults.copy()
            merged.update(settings.get('security', {}))
            settings['security'] = merged

        if 'shop' not in settings:
            settings['shop'] = DEFAULT_SETTINGS.get('shop', {})
        else:
            defaults = DEFAULT_SETTINGS.get('shop', {})
            merged = defaults.copy()
            merged.update(settings.get('shop', {}))
            settings['shop'] = merged
        settings['shop']['fast_transfer_mode'] = _coerce_bool(
            settings['shop'].get('fast_transfer_mode'),
            default=False,
        )

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
        settings['security'] = _normalize_security_settings(settings.get('security'))

        if 'downloads' not in settings:
            settings['downloads'] = DEFAULT_SETTINGS.get('downloads', {})
        else:
            defaults = DEFAULT_SETTINGS.get('downloads', {})
            merged = defaults.copy()
            merged.update(settings.get('downloads', {}))
            settings['downloads'] = merged
        # Keep nested downloads settings backward-compatible when new keys are added.
        prowlarr_defaults = (DEFAULT_SETTINGS.get('downloads', {}) or {}).get('prowlarr', {})
        merged_prowlarr = prowlarr_defaults.copy()
        merged_prowlarr.update((settings['downloads'].get('prowlarr') or {}))
        settings['downloads']['prowlarr'] = merged_prowlarr
        settings['downloads']['search_char_replacements'] = _normalize_download_search_char_replacements(
            settings['downloads'].get('search_char_replacements')
        )

        if 'titles' not in settings:
            settings['titles'] = DEFAULT_SETTINGS.get('titles', {})
        else:
            defaults = DEFAULT_SETTINGS.get('titles', {})
            merged = defaults.copy()
            merged.update(settings.get('titles', {}))
            settings['titles'] = merged
        settings['titles']['manual_overrides'] = _normalize_titles_manual_overrides(
            settings['titles'].get('manual_overrides')
        )

        if 'library' not in settings:
            settings['library'] = DEFAULT_SETTINGS.get('library', {})
        else:
            defaults = DEFAULT_SETTINGS.get('library', {})
            merged = defaults.copy()
            merged.update(settings.get('library', {}))
            settings['library'] = merged
        settings['library']['naming_templates'] = _normalize_library_naming_templates(
            settings['library'].get('naming_templates')
        )

        valid_keys = load_keys()
        settings['titles']['valid_keys'] = valid_keys

    else:
        settings = DEFAULT_SETTINGS
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
        settings['security'] = _normalize_security_settings(settings.get('security'))
        with open(CONFIG_FILE, 'w') as yaml_file:
            yaml.dump(settings, yaml_file)
    settings['security'] = _normalize_security_settings(settings.get('security'))
    settings.setdefault('library', {})
    settings['library']['naming_templates'] = _normalize_library_naming_templates(
        settings['library'].get('naming_templates')
    )
    settings.setdefault('titles', {})
    settings['titles']['manual_overrides'] = _normalize_titles_manual_overrides(
        settings['titles'].get('manual_overrides')
    )
    settings.setdefault('downloads', {})
    settings['downloads']['search_char_replacements'] = _normalize_download_search_char_replacements(
        settings['downloads'].get('search_char_replacements')
    )
    settings.setdefault('shop', {})
    settings['shop']['fast_transfer_mode'] = _coerce_bool(
        settings['shop'].get('fast_transfer_mode'),
        default=False,
    )
    
    # Update cache
    _settings_cache = settings
    _settings_cache_time = current_time
    
    return settings


def set_security_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('security', {})
    settings['security'].update(data or {})
    settings['security'] = _normalize_security_settings(settings.get('security'))
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    # Invalidate cache
    global _settings_cache
    _settings_cache = None

def verify_settings(section, data):
    success = True
    errors = []
    if section == 'library':
        # Check that paths exist
        for dir in data['paths']:
            if not os.path.exists(dir):
                success = False
                errors.append({
                    'path': 'library/path',
                    'error': f"Path {dir} does not exists."
                })
                break
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
    # Invalidate cache
    global _settings_cache
    _settings_cache = None
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
            # Invalidate cache
            global _settings_cache
            _settings_cache = None
        else:
            success = False
            errors.append({
                    'path': 'library/paths',
                    'error': f"Path {path} not configured."
                })
    return success, errors

def set_titles_settings(region, language):
    settings = load_settings(force_reload=True)
    settings['titles']['region'] = region
    settings['titles']['language'] = language
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    # Invalidate cache
    global _settings_cache
    _settings_cache = None

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
        bool(payload.get('screenshots')),
    ])
    if has_value:
        overrides[title_id] = payload
    else:
        overrides.pop(title_id, None)

    settings['titles']['manual_overrides'] = overrides
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    global _settings_cache
    _settings_cache = None
    return True

def set_shop_settings(data):
    settings = load_settings(force_reload=True)
    shop_host = data['host']
    if '://' in shop_host:
        data['host'] = shop_host.split('://')[-1]
    data['fast_transfer_mode'] = _coerce_bool(data.get('fast_transfer_mode'), default=False)
    settings['shop'].update(data)
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    # Invalidate cache
    global _settings_cache
    _settings_cache = None

def set_download_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('downloads', {})
    if data and 'search_char_replacements' in data:
        data['search_char_replacements'] = _normalize_download_search_char_replacements(
            data.get('search_char_replacements')
        )
    settings['downloads'].update(data)
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    # Invalidate cache
    global _settings_cache
    _settings_cache = None

def set_library_settings(data):
    settings = load_settings(force_reload=True)
    settings.setdefault('library', {})
    if data and 'naming_templates' in data:
        data['naming_templates'] = _normalize_library_naming_templates(data.get('naming_templates'))
    settings['library'].update(data)
    with open(CONFIG_FILE, 'w') as yaml_file:
        yaml.dump(settings, yaml_file)
    global _settings_cache
    _settings_cache = None
