from app.constants import *
import yaml
import os
import time

import logging

# Retrieve main logger
logger = logging.getLogger('main')

# Cache for settings
_settings_cache = None
_settings_cache_time = 0
_settings_cache_ttl = 5  # Cache for 5 seconds

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
    if not os.path.isfile(key_file):
        logger.debug(f'Keys file {key_file} does not exist.')
        return valid, ['keys_file_missing']
    try:
        from nsz.nut import Keys
    except Exception as e:
        msg = f'nsz_keys_module_unavailable: {e}'
        logger.debug(msg)
        return valid, [msg]
    try:
        valid = bool(Keys.load(key_file))
        if valid:
            return True, []

        incorrect = []
        loaded = []
        try:
            getter = getattr(Keys, 'getIncorrectKeysRevisions', None)
            if callable(getter):
                incorrect = list(getter() or [])
        except Exception:
            incorrect = []
        try:
            getter = getattr(Keys, 'getLoadedKeysRevisions', None)
            if callable(getter):
                loaded = list(getter() or [])
        except Exception:
            loaded = []

        if loaded:
            logger.warning(
                "Keys loaded with warnings. Loaded revisions: %s, incorrect revisions: %s",
                loaded,
                incorrect,
            )
            return True, []

        if incorrect:
            errors.extend([f"incorrect_{rev}" for rev in incorrect])
        if not errors:
            errors.append('no_valid_master_keys')
        return False, errors
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

        env_trust = _read_env_bool('OWNFOIL_TRUST_PROXY_HEADERS')
        if env_trust is not None:
            settings['security']['trust_proxy_headers'] = env_trust
        env_proxies = _read_env_csv('OWNFOIL_TRUSTED_PROXIES')
        if env_proxies is not None:
            settings['security']['trusted_proxies'] = env_proxies

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
        env_trust = _read_env_bool('OWNFOIL_TRUST_PROXY_HEADERS')
        if env_trust is not None:
            settings['security']['trust_proxy_headers'] = env_trust
        env_proxies = _read_env_csv('OWNFOIL_TRUSTED_PROXIES')
        if env_proxies is not None:
            settings['security']['trusted_proxies'] = env_proxies
        with open(CONFIG_FILE, 'w') as yaml_file:
            yaml.dump(settings, yaml_file)
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
