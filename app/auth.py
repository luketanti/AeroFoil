from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app.db import *
from flask_login import LoginManager
from app.settings import load_settings, set_security_settings
import hashlib

import logging
import threading
import time

# Retrieve main logger
logger = logging.getLogger('main')

_recent_auth_log_lock = threading.Lock()
_recent_auth_log = {}
_auth_ip_state_lock = threading.Lock()
_auth_failed_attempts = {}
_auth_ip_lockouts = {}
_auth_failure_burst_lock = threading.Lock()
_auth_failure_burst = {}
_AUTH_FAILURE_BURST_WINDOW_S = 1.5


def _auth_dedupe_allow(dedupe_key: str, window_s: int = 15) -> bool:
    now = time.time()
    key = str(dedupe_key or '')[:512]
    with _recent_auth_log_lock:
        last = _recent_auth_log.get(key) or 0
        if now - last < float(window_s):
            return False
        _recent_auth_log[key] = now
        if len(_recent_auth_log) > 5000:
            ordered = sorted(_recent_auth_log.items(), key=lambda kv: kv[1], reverse=True)
            _recent_auth_log.clear()
            for k, ts in ordered[:2000]:
                _recent_auth_log[k] = ts
    return True


def _to_bool(value, default=False):
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


def _to_int(value, default=0, minimum=None, maximum=None):
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
    if isinstance(raw, str):
        entries = [raw]
    elif isinstance(raw, (list, tuple, set)):
        entries = list(raw)
    else:
        entries = []

    out = []
    seen = set()
    for entry in entries:
        text = str(entry or '').strip()
        if not text:
            continue
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


def _get_auth_protection_config(settings):
    security = (settings or {}).get('security', {}) or {}
    return {
        'lockout_enabled': _to_bool(security.get('auth_ip_lockout_enabled'), default=True),
        'threshold': _to_int(security.get('auth_ip_lockout_threshold'), default=5, minimum=1, maximum=1000),
        'window_s': _to_int(security.get('auth_ip_lockout_window_seconds'), default=600, minimum=10, maximum=86400),
        'duration_s': _to_int(security.get('auth_ip_lockout_duration_seconds'), default=1800, minimum=10, maximum=604800),
        'permanent_blacklist': _normalize_ip_entries(security.get('auth_permanent_ip_blacklist')),
    }


def _ip_matches_entry(ip_value, entry):
    try:
        import ipaddress
        target_ip = ipaddress.ip_address(str(ip_value or '').strip())
        token = str(entry or '').strip()
        if not token:
            return False
        if '/' in token:
            return target_ip in ipaddress.ip_network(token, strict=False)
        return target_ip == ipaddress.ip_address(token)
    except Exception:
        return False


def _is_permanently_blocked_ip(client_ip, config):
    if not client_ip:
        return False
    for entry in config.get('permanent_blacklist') or []:
        if _ip_matches_entry(client_ip, entry):
            return True
    return False


def _temporary_lockout_remaining_s(client_ip):
    if not client_ip:
        return 0
    now = time.time()
    with _auth_ip_state_lock:
        lockout_until = float(_auth_ip_lockouts.get(client_ip) or 0.0)
        if lockout_until <= now:
            _auth_ip_lockouts.pop(client_ip, None)
            return 0
        return int(max(1, round(lockout_until - now)))


def _is_ip_blocked(client_ip, config):
    if _is_permanently_blocked_ip(client_ip, config):
        return True, 'permanent', 0
    remaining_s = _temporary_lockout_remaining_s(client_ip)
    if remaining_s > 0:
        return True, 'temporary', remaining_s
    return False, None, 0


def _record_auth_failure(client_ip, config):
    if not client_ip:
        return False, 0
    if not bool(config.get('lockout_enabled')):
        return False, 0

    threshold = int(config.get('threshold') or 5)
    window_s = int(config.get('window_s') or 600)
    duration_s = int(config.get('duration_s') or 1800)
    now = time.time()
    cutoff = now - float(window_s)
    lockout_triggered = False

    with _auth_ip_state_lock:
        attempts = [
            ts for ts in (_auth_failed_attempts.get(client_ip) or [])
            if float(ts) >= cutoff
        ]
        attempts.append(now)
        # Bound per-IP attempt history.
        attempts = attempts[-max(threshold * 4, threshold):]
        _auth_failed_attempts[client_ip] = attempts
        if len(attempts) >= threshold:
            _auth_ip_lockouts[client_ip] = now + float(duration_s)
            lockout_triggered = True

        # Bound global structures.
        if len(_auth_failed_attempts) > 5000:
            ordered = sorted(
                _auth_failed_attempts.items(),
                key=lambda kv: (kv[1][-1] if kv[1] else 0),
                reverse=True
            )
            _auth_failed_attempts.clear()
            for key, value in ordered[:2000]:
                _auth_failed_attempts[key] = value
        if len(_auth_ip_lockouts) > 5000:
            active = {
                key: until for key, until in _auth_ip_lockouts.items()
                if float(until or 0) > now
            }
            ordered = sorted(active.items(), key=lambda kv: kv[1], reverse=True)
            _auth_ip_lockouts.clear()
            for key, value in ordered[:2000]:
                _auth_ip_lockouts[key] = value

    return lockout_triggered, int(duration_s)


def _clear_auth_failures(client_ip):
    if not client_ip:
        return
    with _auth_ip_state_lock:
        _auth_failed_attempts.pop(client_ip, None)
        _auth_ip_lockouts.pop(client_ip, None)


def _should_count_failure(client_ip, username=None, password=None):
    """Collapse duplicate failed auth checks for the same credential burst.

    Some clients probe multiple endpoints in parallel with identical bad creds.
    Count that as a single failed attempt for lockout purposes.
    """
    ip = str(client_ip or '').strip()
    if not ip:
        return True
    uname = str(username or '').strip().lower()
    secret = str(password or '')
    digest = hashlib.sha256(f"{uname}\x00{secret}".encode('utf-8', errors='ignore')).hexdigest()
    key = f"{ip}|{digest}"
    now = time.time()
    with _auth_failure_burst_lock:
        last = float(_auth_failure_burst.get(key) or 0.0)
        if (now - last) < float(_AUTH_FAILURE_BURST_WINDOW_S):
            return False
        _auth_failure_burst[key] = now
        if len(_auth_failure_burst) > 20000:
            cutoff = now - float(_AUTH_FAILURE_BURST_WINDOW_S) * 4.0
            keep = {
                k: ts for k, ts in _auth_failure_burst.items()
                if float(ts) >= cutoff
            }
            if len(keep) > 10000:
                ordered = sorted(keep.items(), key=lambda kv: kv[1], reverse=True)[:10000]
                keep = {k: v for k, v in ordered}
            _auth_failure_burst.clear()
            _auth_failure_burst.update(keep)
    return True


def _get_active_lockouts_snapshot():
    settings = {}
    try:
        settings = load_settings()
    except Exception:
        settings = {}
    config = _get_auth_protection_config(settings)
    window_s = int(config.get('window_s') or 600)
    now = time.time()

    items = []
    with _auth_ip_state_lock:
        expired_ips = [
            ip for ip, until in _auth_ip_lockouts.items()
            if float(until or 0) <= now
        ]
        for ip in expired_ips:
            _auth_ip_lockouts.pop(ip, None)

        for ip, until in _auth_ip_lockouts.items():
            remaining = int(max(1, round(float(until or 0) - now)))
            attempts = [
                ts for ts in (_auth_failed_attempts.get(ip) or [])
                if float(ts) >= (now - float(window_s))
            ]
            _auth_failed_attempts[ip] = attempts
            last_failed_at = int(max(attempts)) if attempts else None
            items.append({
                'ip': str(ip),
                'remaining_seconds': remaining,
                'locked_until': int(float(until or 0)),
                'failed_attempts_recent': len(attempts),
                'last_failed_at': last_failed_at,
                'window_seconds': window_s,
            })

    items.sort(key=lambda item: int(item.get('remaining_seconds') or 0), reverse=True)
    return items


def _unlock_ip_lockout(ip_value):
    ip = str(ip_value or '').strip()
    if not ip:
        return False
    removed = False
    with _auth_ip_state_lock:
        if _auth_ip_lockouts.pop(ip, None) is not None:
            removed = True
        if _auth_failed_attempts.pop(ip, None) is not None:
            removed = True
    return removed


def _unlock_all_ip_lockouts():
    with _auth_ip_state_lock:
        removed = len(_auth_ip_lockouts)
        _auth_ip_lockouts.clear()
        _auth_failed_attempts.clear()
    return int(removed)


def _log_login_event(kind: str, username: str = None, ok: bool = None, status_code: int = None, window_s: int = 10):
    try:
        settings = {}
        try:
            settings = load_settings()
        except Exception:
            settings = {}
        remote = _effective_client_ip(settings)
        ua = request.headers.get('User-Agent')

        # Dedupe noisy auth failures (scanners, repeated retries).
        dedupe_key = f"{kind}|{(username or '').strip()}|{remote}|{ua}"[:512]
        if window_s and not _auth_dedupe_allow(dedupe_key, window_s=window_s):
            return

        add_access_event(
            kind=kind,
            user=(username or '').strip() or None,
            remote_addr=remote,
            user_agent=ua,
            ok=bool(ok) if ok is not None else None,
            status_code=(
                int(status_code)
                if status_code is not None
                else (200 if ok else 401)
            ),
        )
    except Exception:
        # Avoid breaking auth flow on logging failures.
        try:
            logger.exception('Failed to log login event')
        except Exception:
            pass

def admin_account_created():
    # Setup mode is active until at least one admin user exists.
    # If setup was explicitly completed, do not fall back into setup mode.
    try:
        settings = load_settings()
        if _setup_complete(settings):
            return True
    except Exception:
        pass

    try:
        return User.query.filter_by(admin_access=True).count() > 0
    except Exception:
        return False


def _setup_complete(settings: dict) -> bool:
    try:
        return bool((settings or {}).get('security', {}).get('setup_complete', False))
    except Exception:
        return False


def _bootstrap_private_only(settings: dict) -> bool:
    try:
        return bool((settings or {}).get('security', {}).get('bootstrap_private_networks_only', True))
    except Exception:
        return True


def _trusted_proxies(settings: dict):
    try:
        return list((settings or {}).get('security', {}).get('trusted_proxies') or [])
    except Exception:
        return []


def _trust_proxy_headers(settings: dict) -> bool:
    try:
        return bool((settings or {}).get('security', {}).get('trust_proxy_headers', False))
    except Exception:
        return False


def _peer_ip() -> str:
    return (request.remote_addr or '').strip()


def _parse_ip_for_match(value):
    try:
        import ipaddress
        text = str(value or '').strip()
        if not text:
            return None
        # Accept bracketed literals from some proxy/server representations.
        if text.startswith('[') and text.endswith(']'):
            text = text[1:-1].strip()
        ip = ipaddress.ip_address(text)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        return ip
    except Exception:
        return None


def _normalize_ip_text(value: str) -> str:
    ip = _parse_ip_for_match(value)
    if ip is None:
        return ''
    return str(ip)


def _is_ip_in_trusted_proxy_ranges(ip_value: str, settings: dict) -> bool:
    try:
        import ipaddress
        ip_obj = _parse_ip_for_match(ip_value)
        if ip_obj is None:
            return False
        entries = _trusted_proxies(settings)
        if not entries:
            return False
        for entry in entries:
            entry = str(entry).strip()
            if not entry:
                continue
            try:
                if '/' in entry:
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    entry_ip = _parse_ip_for_match(entry)
                    if entry_ip is not None and ip_obj == entry_ip:
                        return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _parse_ip_header_list(value: str):
    out = []
    seen = set()
    for raw in str(value or '').split(','):
        normalized = _normalize_ip_text(raw)
        if not normalized:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def _peer_is_trusted_proxy(settings: dict) -> bool:
    try:
        peer = _peer_ip()
        if not peer:
            return False
        return _is_ip_in_trusted_proxy_ranges(peer, settings)
    except Exception:
        return False


def _effective_client_ip(settings: dict) -> str:
    """Return client IP, trusting proxy headers only from configured proxies."""
    peer = _peer_ip()
    xff = (request.headers.get('X-Forwarded-For') or '').strip()
    if xff and _trust_proxy_headers(settings) and _peer_is_trusted_proxy(settings):
        # Prefer the right-most non-trusted IP from XFF chain.
        # This is resilient to multi-proxy append behavior and odd ordering.
        xff_chain = _parse_ip_header_list(xff)
        while xff_chain and _is_ip_in_trusted_proxy_ranges(xff_chain[-1], settings):
            xff_chain.pop()
        candidate = xff_chain[-1] if xff_chain else ''
        if candidate:
            return candidate
        # Fallback for proxy stacks that only set one real-client header.
        for header_name in ('CF-Connecting-IP', 'True-Client-IP', 'X-Real-IP'):
            header_value = _normalize_ip_text(request.headers.get(header_name) or '')
            if header_value and not _is_ip_in_trusted_proxy_ranges(header_value, settings):
                return header_value
    return peer


def _is_private_ip(value: str) -> bool:
    try:
        import ipaddress
        if not value:
            return False
        ip = ipaddress.ip_address(value)
        return bool(ip.is_private or ip.is_loopback)
    except Exception:
        return False


def _bootstrap_request_allowed(settings: dict) -> bool:
    """Bootstrap is only allowed from private networks.

    If a reverse proxy is used (X-Forwarded-For present), require explicit proxy trust config.
    """
    peer = _peer_ip()
    xff = (request.headers.get('X-Forwarded-For') or '').strip()

    if xff:
        # Don't trust XFF unless explicitly configured and peer is trusted.
        if not _trust_proxy_headers(settings) or not _peer_is_trusted_proxy(settings):
            return False
        client = _effective_client_ip(settings)
        return _is_private_ip(client)

    # Direct connection.
    return _is_private_ip(peer)


def _render_setup_required(reason: str = ''):
    peer = _peer_ip()
    xff = (request.headers.get('X-Forwarded-For') or '').strip()
    return render_template(
        'setup_required.html',
        title='Setup required',
        reason=reason,
        peer_addr=peer,
        x_forwarded_for=xff,
    ), 403

def unauthorized_json():
    response = login_manager.unauthorized()
    resp = {
        'success': False,
        'status_code': response.status_code,
        'location': response.location
    }
    return jsonify(resp)

def access_required(access: str):
    def _access_required(f):
        @wraps(f)
        def decorated_view(*args, **kwargs):
            if not admin_account_created():
                # Setup mode: do NOT disable auth globally.
                # Optionally allow bootstrap only from private networks.
                _app_settings = {}
                try:
                    _app_settings = load_settings()
                except Exception:
                    _app_settings = {}

                if _setup_complete(_app_settings):
                    # Safety latch: don't ever re-enter setup mode automatically.
                    return 'Forbidden', 403

                setup_allow = (access == 'admin' and request.path in ('/users', '/api/user/signup'))
                if _bootstrap_private_only(_app_settings) and not _bootstrap_request_allowed(_app_settings):
                    # Show a friendly page to non-private clients during setup.
                    if request.path.startswith('/api/'):
                        return jsonify({'success': False, 'error': 'Forbidden'}), 403
                    reason = 'Access denied from this network during initial setup.'
                    if request.headers.get('X-Forwarded-For'):
                        reason = reason + ' Reverse proxy detected; configure security.trusted_proxies and enable security.trust_proxy_headers.'
                    return _render_setup_required(reason)

                if setup_allow:
                    return f(*args, **kwargs)

                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Setup required: create the first admin user at /users.'}), 403
                return redirect('/users')

            if not current_user.is_authenticated:
                # return unauthorized_json()
                return login_manager.unauthorized()

            if not current_user.has_access(access):
                return 'Forbidden', 403
            return f(*args, **kwargs)
        return decorated_view
    return _access_required


def roles_required(roles: list, require_all=False):
    def _roles_required(f):
        @wraps(f)
        def decorated_view(*args, **kwargs):
            if not roles:
                raise ValueError('Empty list used when requiring a role.')
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if require_all and not all(current_user.has_role(role) for role in roles):
                return 'Forbidden', 403
            elif not require_all and not any(current_user.has_role(role) for role in roles):
                return 'Forbidden', 403
            return f(*args, **kwargs)

        return decorated_view

    return _roles_required

def basic_auth(request):
    success = True
    error = ''
    is_admin = False
    settings = {}
    try:
        settings = load_settings()
    except Exception:
        settings = {}
    auth_config = _get_auth_protection_config(settings)
    client_ip = _effective_client_ip(settings)

    blocked, block_reason, remaining_s = _is_ip_blocked(client_ip, auth_config)
    if blocked:
        success = False
        if block_reason == 'permanent':
            error = 'Access blocked for this client IP.'
            _log_login_event('shop_auth_blocked_permanent_ip', username=None, ok=False, status_code=403, window_s=30)
        else:
            error = f'Too many failed attempts from this client IP. Try again in {int(remaining_s)}s.'
            _log_login_event('shop_auth_blocked_temporary_ip', username=None, ok=False, status_code=429, window_s=15)
        return success, error, is_admin

    auth = request.authorization
    if auth is None:
        success = False
        error = 'Shop requires authentication.'
        _log_login_event('shop_auth_missing', username=None, ok=False, status_code=401, window_s=30)
        return success, error, is_admin

    username = auth.username
    password = auth.password
    user = User.query.filter_by(user=username).first()
    if user is None:
        success = False
        error = f'Unknown user "{username}".'
        _log_login_event('shop_auth_failed_unknown_user', username=username, ok=False, status_code=401, window_s=30)
        if _should_count_failure(client_ip, username=username, password=password):
            lockout_triggered, _ = _record_auth_failure(client_ip, auth_config)
            if lockout_triggered:
                _log_login_event('shop_auth_lockout_activated', username=username, ok=False, status_code=429, window_s=10)
    
    elif not check_password_hash(user.password, password):
        success = False
        error = f'Incorrect password for user "{username}".'
        _log_login_event('shop_auth_failed_bad_password', username=username, ok=False, status_code=401, window_s=30)
        if _should_count_failure(client_ip, username=username, password=password):
            lockout_triggered, _ = _record_auth_failure(client_ip, auth_config)
            if lockout_triggered:
                _log_login_event('shop_auth_lockout_activated', username=username, ok=False, status_code=429, window_s=10)

    elif getattr(user, 'frozen', False):
        success = False
        message = (getattr(user, 'frozen_message', None) or '').strip()
        error = message if message else 'Account is frozen.'
        _log_login_event('shop_auth_denied_frozen', username=username, ok=False, status_code=403, window_s=60)

    elif not user.has_shop_access():
        success = False
        error = f'User "{username}" does not have access to the shop.'
        _log_login_event('shop_auth_denied_no_access', username=username, ok=False, status_code=403, window_s=60)

    else:
        is_admin = user.has_admin_access()
        _clear_auth_failures(client_ip)
        # Basic auth may be sent on every request; dedupe to avoid log spam.
        _log_login_event('shop_auth_success', username=username, ok=True, status_code=200, window_s=60)
    return success, error, is_admin

auth_blueprint = Blueprint('auth', __name__)

login_manager = LoginManager()
login_manager.login_view = 'auth.login'

def create_or_update_user(username, password, admin_access=False, shop_access=False, backup_access=False):
    """
    Create a new user or update an existing user with the given credentials and access rights.
    """
    user = User.query.filter_by(user=username).first()
    if user:
        logger.info(f'Updating existing user {username}')
        user.admin_access = admin_access
        user.shop_access = shop_access
        user.backup_access = backup_access
        if getattr(user, 'frozen', False) and admin_access:
            user.frozen = False
            user.frozen_message = None
        user.password = generate_password_hash(password, method='scrypt')
    else:
        logger.info(f'Creating new user {username}')
        new_user = User(user=username, password=generate_password_hash(password, method='scrypt'), admin_access=admin_access, shop_access=shop_access, backup_access=backup_access)
        db.session.add(new_user)
    db.session.commit()

def init_user_from_environment(environment_name, admin=False):
    """
    allow to init some user from environment variable to init some users without using the UI
    """
    username = os.getenv(environment_name + '_NAME')
    password = os.getenv(environment_name + '_PASSWORD')
    if username and password:
        if admin:
            logger.info('Initializing an admin user from environment variable...')
            admin_access = True
            shop_access = True
            backup_access = True
        else:
            logger.info('Initializing a regular user from environment variable...')
            admin_access = False
            shop_access = True
            backup_access = False

        if not admin:
            existing_admin = admin_account_created()
            if not existing_admin and not admin_access:
                logger.error(f'Error creating user {username}, first account created must be admin')
                return

        create_or_update_user(username, password, admin_access, shop_access, backup_access)

def init_users(app):
    with app.app_context():
        # init users from ENV
        if os.environ.get('USER_ADMIN_NAME') is not None:
            init_user_from_environment(environment_name="USER_ADMIN", admin=True)
        if os.environ.get('USER_GUEST_NAME') is not None:
            init_user_from_environment(environment_name="USER_GUEST", admin=False)

@auth_blueprint.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        next_url = request.args.get('next', '')
        if current_user.is_authenticated:
            return redirect(next_url if len(next_url) else '/')
        return render_template('login.html', title='Login')
        
    # login code goes here
    username = request.form.get('user')
    password = request.form.get('password')
    remember = bool(request.form.get('remember'))
    next_url = request.form.get('next', '')
    settings = {}
    try:
        settings = load_settings()
    except Exception:
        settings = {}
    auth_config = _get_auth_protection_config(settings)
    client_ip = _effective_client_ip(settings)

    blocked, block_reason, remaining_s = _is_ip_blocked(client_ip, auth_config)
    if blocked:
        if block_reason == 'permanent':
            logger.warning(f'Blocked web login from permanently blacklisted IP {client_ip}')
            _log_login_event('login_blocked_permanent_ip', username=username, ok=False, status_code=403, window_s=15)
        else:
            logger.warning(f'Blocked web login from temporarily locked IP {client_ip}, remaining {remaining_s}s')
            _log_login_event('login_blocked_temporary_ip', username=username, ok=False, status_code=429, window_s=10)
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(user=username).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user:
        logger.warning(f'Incorrect login for user {username}')
        _log_login_event('login_failed_unknown_user', username=username, ok=False, status_code=401, window_s=15)
        if _should_count_failure(client_ip, username=username, password=password):
            lockout_triggered, _ = _record_auth_failure(client_ip, auth_config)
            if lockout_triggered:
                _log_login_event('login_lockout_activated', username=username, ok=False, status_code=429, window_s=10)
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not check_password_hash(user.password, password):
        logger.warning(f'Incorrect login for user {username}')
        _log_login_event('login_failed_bad_password', username=username, ok=False, status_code=401, window_s=15)
        if _should_count_failure(client_ip, username=username, password=password):
            lockout_triggered, _ = _record_auth_failure(client_ip, auth_config)
            if lockout_triggered:
                _log_login_event('login_lockout_activated', username=username, ok=False, status_code=429, window_s=10)
        return redirect(url_for('auth.login'))

    if getattr(user, 'frozen', False):
        logger.warning(f'Blocked login for frozen user {username}')
        _log_login_event('login_denied_frozen', username=username, ok=False, status_code=403, window_s=30)
        return redirect(url_for('auth.login'))

    # if the above check passes, then we know the user has the right credentials
    logger.info(f'Sucessfull login for user {username}')
    _clear_auth_failures(client_ip)
    login_user(user, remember=remember)
    _log_login_event('login_success', username=username, ok=True, status_code=200, window_s=0)

    return redirect(next_url if len(next_url) else '/')

@auth_blueprint.route('/profile')
@login_required
@access_required('backup')
def profile():
    return render_template('profile.html')

@auth_blueprint.route('/api/users')
@access_required('admin')
def get_users():
    all_users = [
        dict(db_user._mapping)
        for db_user in db.session.query(
            User.id,
            User.user,
            User.admin_access,
            User.shop_access,
            User.backup_access,
            User.frozen,
            User.frozen_message,
        ).all()
    ]
    return jsonify(all_users)


@auth_blueprint.route('/api/auth/lockouts', methods=['GET'])
@access_required('admin')
def get_auth_lockouts():
    try:
        items = _get_active_lockouts_snapshot()
        return jsonify({
            'success': True,
            'items': items,
            'count': len(items),
            'timestamp': int(time.time()),
        })
    except Exception as e:
        logger.error(f'Failed to list auth lockouts: {e}')
        return jsonify({'success': False, 'error': 'Failed to list auth lockouts.'}), 500


@auth_blueprint.route('/api/auth/lockouts/unlock', methods=['POST'])
@access_required('admin')
def unlock_auth_lockout():
    data = request.json or {}
    ip = str(data.get('ip') or '').strip()
    if not ip:
        return jsonify({'success': False, 'error': 'Missing ip.'}), 400
    removed = _unlock_ip_lockout(ip)
    logger.info(f'Auth lockout unlock requested for {ip}: removed={removed}')
    return jsonify({'success': True, 'ip': ip, 'removed': bool(removed)})


@auth_blueprint.route('/api/auth/lockouts/unlock-all', methods=['POST'])
@access_required('admin')
def unlock_all_auth_lockouts():
    removed = _unlock_all_ip_lockouts()
    logger.info(f'Auth lockout unlock-all requested: removed={removed}')
    return jsonify({'success': True, 'removed': int(removed)})


@auth_blueprint.route('/api/user/freeze', methods=['PATCH'])
@login_required
@access_required('admin')
def freeze_user():
    success = True
    errors = []
    data = request.json or {}
    user_id = data.get('user_id')
    frozen = data.get('frozen')
    message = (data.get('message') or '').strip()

    if not user_id:
        errors.append('Missing user id.')
    if frozen is None:
        errors.append('Missing frozen state.')

    user = User.query.filter_by(id=user_id).first() if not errors else None
    if not user:
        errors.append('User not found.')

    if errors:
        success = False
    else:
        user.frozen = bool(frozen)
        user.frozen_message = message if user.frozen else None
        db.session.commit()
        logger.info(f"Updated frozen state for user {user.id} ({user.user}): {user.frozen}")

    return jsonify({'success': success, 'errors': errors})

@auth_blueprint.route('/api/user', methods=['DELETE'])
@login_required
@access_required('admin')
def delete_user():
    data = request.json or {}
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'Missing user_id.'}), 400

    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    # Prevent accidentally removing the last admin account.
    if bool(getattr(user, 'admin_access', False)):
        admin_count = User.query.filter_by(admin_access=True).count()
        if admin_count <= 1:
            return jsonify({'success': False, 'error': 'Cannot delete the last admin account.'}), 400

    try:
        User.query.filter_by(id=user_id).delete()
        db.session.commit()
        logger.info(f'Successfully deleted user with id {user_id}.')
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f'Could not delete user with id {user_id}: {e}')
        return jsonify({'success': False, 'error': 'Delete failed.'}), 500

@auth_blueprint.route('/api/user', methods=['PATCH'])
@login_required
@access_required('admin')
def update_user():
    success = True
    errors = []
    data = request.json or {}
    user_id = data.get('user_id')
    username = (data.get('user') or '').strip()
    password = data.get('password')
    admin_access = data.get('admin_access')
    shop_access = data.get('shop_access')
    backup_access = data.get('backup_access')

    if not user_id:
        errors.append('Missing user id.')
    if not username:
        errors.append('Username is required.')
    if admin_access is None or shop_access is None or backup_access is None:
        errors.append('Missing access configuration.')

    user = User.query.filter_by(id=user_id).first() if not errors else None
    if not user:
        errors.append('User not found.')

    if user and username != user.user:
        existing_user = User.query.filter_by(user=username).first()
        if existing_user:
            errors.append('Username already exists.')

    if user and user.admin_access and admin_access is False:
        admin_count = User.query.filter_by(admin_access=True).count()
        if admin_count <= 1:
            errors.append('Cannot remove the last admin account.')

    if errors:
        success = False
    else:
        if admin_access:
            shop_access = True
            backup_access = True
        user.user = username
        user.admin_access = admin_access
        user.shop_access = shop_access
        user.backup_access = backup_access
        if getattr(user, 'frozen', False) and admin_access:
            user.frozen = False
            user.frozen_message = None
        if password:
            user.password = generate_password_hash(password, method='scrypt')
        db.session.commit()
        logger.info(f'Successfully updated user {user.id} ({username}).')

    resp = {
        'success': success,
        'errors': errors
    }
    return jsonify(resp)

@auth_blueprint.route('/api/user/password', methods=['PATCH'])
@login_required
@access_required('admin')
def reset_user_password():
    success = True
    errors = []
    data = request.json or {}
    user_id = data.get('user_id')
    password = data.get('password')

    if not user_id:
        errors.append('Missing user id.')
    if not password:
        errors.append('Password is required.')

    user = User.query.filter_by(id=user_id).first() if not errors else None
    if not user:
        errors.append('User not found.')

    if errors:
        success = False
    else:
        user.password = generate_password_hash(password, method='scrypt')
        db.session.commit()
        logger.info(f'Successfully reset password for user {user.id} ({user.user}).')

    resp = {
        'success': success,
        'errors': errors
    }
    return jsonify(resp)

@auth_blueprint.route('/api/user/signup', methods=['POST'])
@access_required('admin')
def signup_post():
    signup_success = True
    data = request.json

    username = data['user']
    password = data['password']
    admin_access = data['admin_access']
    if admin_access:
        shop_access = True
        backup_access = True
    else:
        shop_access = data['shop_access']
        backup_access = data['backup_access']

    user = User.query.filter_by(user=username).first() # if this returns a user, then the user already exists in database
    
    if user: # if a user is found, we want to redirect back to signup page so user can try again
        logger.error(f'Error creating user {username}, user already exists')
        # Todo redirect to incoming page or return success: false
        return redirect(url_for('auth.signup'))
    
    existing_admin = admin_account_created()
    if not existing_admin and not admin_access:
        logger.error(f'Error creating user {username}, first account created must be admin')
        resp = {
            'success': False,
            'status_code': 400,
            'location': '/settings',
        } 
        return jsonify(resp)

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    create_or_update_user(username, password, admin_access, shop_access, backup_access)
    
    logger.info(f'Successfully created user {username}.')

    resp = {
        'success': signup_success
    } 

    if not existing_admin and admin_access:
        logger.debug('First admin account created')
        try:
            set_security_settings({'setup_complete': True})
        except Exception:
            pass
        resp['status_code'] = 302,
        resp['location'] = '/settings'
    
    return jsonify(resp)


@auth_blueprint.route('/logout')
@login_required
def logout():
    try:
        username = None
        try:
            if current_user.is_authenticated:
                username = current_user.user
        except Exception:
            username = None
        _log_login_event('logout', username=username, ok=True, status_code=200, window_s=0)
    except Exception:
        pass
    logout_user()
    return redirect('/')
