import logging
import os
import re
import shutil
import sqlite3
import threading
import time
import uuid
import unicodedata
import json

from app import titles as titles_lib
from app.constants import ALLOWED_EXTENSIONS, APP_TYPE_BASE, APP_TYPE_DLC, APP_TYPE_UPD
from app.constants import DATA_DIR
from app.db import get_all_title_apps, get_all_titles, get_libraries_path
from app.downloads.client import (
    get_download_client_capabilities,
    get_download_client_diagnostics,
    list_active_downloads,
    list_completed_downloads,
    list_history_downloads,
    queue_download,
    remove_active_download,
    remove_completed_download,
)
from app.downloads.prowlarr import ProwlarrClient, filter_results, pick_best_result
from app.downloads.versioning import extract_internal_update_version
from app.library import _ensure_unique_path, _sanitize_component, enqueue_cleanup_roots, enqueue_organize_paths
from app.settings import load_settings
from app.utils import get_supported_content_extension, is_supported_content_path, is_wrapped_content_path
logger = logging.getLogger("downloads.manager")

_state_lock = threading.Lock()
_state = {
    "running": False,
    "last_run": 0.0,
    "pending": {},  # key -> info
    "completed": set(),
    "completed_identities": set(),
    "duplicates": [],
}
_state_loaded = False
_DOWNLOADS_STATE_FILE = os.path.join(DATA_DIR, "downloads_state.json")
_DOWNLOADS_CONTENT_INDEX_FILE = os.path.join(DATA_DIR, "downloads_content.index.sqlite3")
_SNAKE_PASS_BASE_TITLE_ID = "0100B3A017864000"
_SNAKE_PASS_BASE_MIN_VERSION = 1
_PENDING_MISSING_GRACE_SECONDS = 30


def _get_prowlarr_timeout_seconds(prowlarr_cfg):
    try:
        timeout_seconds = int((prowlarr_cfg or {}).get("timeout_seconds") or 15)
    except (TypeError, ValueError):
        timeout_seconds = 15
    return max(5, min(timeout_seconds, 180))


def _get_prowlarr_search_limit(prowlarr_cfg):
    try:
        search_limit = int((prowlarr_cfg or {}).get("search_limit") or 100)
    except (TypeError, ValueError):
        search_limit = 100
    return max(1, min(search_limit, 500))


def _get_torrent_min_seeders(downloads):
    try:
        min_seeders = int(((downloads or {}).get("torrent_client") or {}).get("min_seeders") or 0)
    except (TypeError, ValueError):
        min_seeders = 0
    return max(min_seeders, 0)


def _get_usenet_min_age_minutes(downloads):
    try:
        min_age_minutes = int(((downloads or {}).get("usenet_client") or {}).get("min_age_minutes") or 0)
    except (TypeError, ValueError):
        min_age_minutes = 0
    return max(min_age_minutes, 0)


def _infer_protocol(download_url=None, explicit_protocol=None):
    protocol = str(explicit_protocol or "").strip().lower()
    if protocol in ("torrent", "usenet"):
        return protocol
    lowered = str(download_url or "").strip().lower()
    if lowered.startswith("magnet:") or ".torrent" in lowered:
        return "torrent"
    if ".nzb" in lowered or "newznab" in lowered or "usenet" in lowered:
        return "usenet"
    return ""


def _get_protocol_client_cfg(downloads, protocol):
    downloads = downloads or {}
    protocol = str(protocol or "").strip().lower()
    shared_category = str(downloads.get("category") or "").strip()
    if protocol == "torrent":
        cfg = dict(downloads.get("torrent_client", {}) or {})
        if shared_category:
            cfg["category"] = shared_category
        return cfg
    if protocol == "usenet":
        cfg = dict(downloads.get("usenet_client", {}) or {})
        if shared_category:
            cfg["category"] = shared_category
        return cfg
    return {}


def _is_protocol_client_configured(downloads, protocol):
    client_cfg = _get_protocol_client_cfg(downloads, protocol)
    diagnostics = get_download_client_diagnostics(protocol, client_cfg)
    capabilities = (diagnostics or {}).get("capabilities")
    if not isinstance(capabilities, dict):
        return False
    resolved_protocol = str(capabilities.get("protocol") or "").strip().lower()
    if resolved_protocol != str(protocol or "").strip().lower():
        return False
    missing = set(str(field or "").strip().lower() for field in ((diagnostics or {}).get("missing") or []))
    if "url" in missing:
        return False
    if resolved_protocol == "usenet":
        return not any(field in missing for field in ("api_key", "username", "password"))
    return True


def _get_configured_protocols(downloads):
    return [
        protocol for protocol in ("torrent", "usenet")
        if _is_protocol_client_configured(downloads, protocol)
    ]


def get_configured_download_protocols(downloads):
    return _get_configured_protocols(downloads)


def filter_download_search_results(results, downloads, blacklist_terms=None):
    downloads = downloads or {}
    filtered = filter_results(
        results,
        min_seeders=_get_torrent_min_seeders(downloads),
        min_age_minutes=_get_usenet_min_age_minutes(downloads),
        required_terms=downloads.get("required_terms") or [],
        required_terms_match=downloads.get("required_terms_match") or "all",
        blacklist_terms=(downloads.get("blacklist_terms") or []) + (blacklist_terms or []),
    )
    allowed_protocols = _get_configured_protocols(downloads)
    if allowed_protocols:
        filtered = [
            item for item in filtered
            if str(item.get("protocol") or "").strip().lower() in allowed_protocols
        ]
    return filtered


def _download_result_age_sort_key(item):
    try:
        age_minutes = int(item.get("age_minutes"))
    except (TypeError, ValueError, AttributeError):
        return (1, float("inf"))
    return (0, max(age_minutes, 0))


def sort_download_search_results(results):
    return sorted(
        results or [],
        key=lambda item: (
            _download_result_age_sort_key(item),
            str(item.get("indexer") or "").strip().lower(),
            str(item.get("title") or "").strip().lower(),
        ),
    )


def get_download_ui_visibility(downloads):
    return {
        "show_protocol_column": True,
        "show_torrent_columns": _is_protocol_client_configured(downloads, "torrent"),
        "show_usenet_columns": _is_protocol_client_configured(downloads, "usenet"),
    }


def _get_download_capability_warnings(downloads):
    warnings = []
    for protocol in ("torrent", "usenet"):
        if not _is_protocol_client_configured(downloads, protocol):
            continue
        client_cfg = _get_protocol_client_cfg(downloads, protocol)
        capabilities = get_download_client_capabilities(protocol, client_cfg) or {}
        if capabilities.get("supports_live_status", True):
            continue
        client_type = str(capabilities.get("type") or client_cfg.get("type") or "unknown").strip().lower() or "unknown"
        warnings.append(
            f"{protocol.capitalize()} client '{client_type}' does not support live status listing in AeroFoil. "
            "Current Downloads may appear empty and queue completion tracking may be limited."
        )
    return warnings


def _get_completed_poll_targets(downloads):
    targets = []
    for protocol in ("torrent", "usenet"):
        if _is_protocol_client_configured(downloads, protocol):
            targets.append((protocol, _get_protocol_client_cfg(downloads, protocol)))
    return targets


def _get_download_activity_snapshot(downloads):
    active_by_protocol = {}
    completed_by_protocol = {}
    errors_by_protocol = {}
    for protocol, client_cfg in _get_completed_poll_targets(downloads):
        protocol_errors = []
        try:
            active_items = list_active_downloads(protocol, client_cfg)
        except Exception as exc:
            logger.warning("Failed to load active %s downloads: %s", protocol, exc)
            active_items = []
            protocol_errors.append(f"active: {exc}")
        try:
            completed_items = list_history_downloads(protocol, client_cfg)
        except Exception as exc:
            logger.warning("Failed to load completed %s downloads: %s", protocol, exc)
            completed_items = []
            protocol_errors.append(f"completed: {exc}")
        active_by_protocol[protocol] = {
            "client_cfg": client_cfg,
            "items": active_items,
        }
        completed_by_protocol[protocol] = {
            "client_cfg": client_cfg,
            "items": completed_items,
        }
        if protocol_errors:
            errors_by_protocol[protocol] = protocol_errors
    return {
        "active_by_protocol": active_by_protocol,
        "completed_by_protocol": completed_by_protocol,
        "errors_by_protocol": errors_by_protocol,
    }


def _normalize_queue_state_label(status):
    text = re.sub(r"\s+", " ", str(status or "").strip().lower())
    if not text:
        return "downloading"
    if "download" in text:
        return "downloading"
    if "pause" in text:
        return "paused"
    if "queue" in text:
        return "queued"
    if "stall" in text:
        return "stalled"
    if "meta" in text or "check" in text:
        return "preparing"
    if "seed" in text or "upload" in text:
        return "seeding"
    return text


def _normalize_terminal_queue_state(item):
    if isinstance(item, dict):
        explicit_state = str(item.get("state") or "").strip().lower()
        if explicit_state in ("completed", "failed", "cancelled"):
            return explicit_state
        status_text = str(item.get("status") or "").strip().lower()
    else:
        explicit_state = str(item or "").strip().lower()
        if explicit_state in ("completed", "failed", "cancelled"):
            return explicit_state
        status_text = explicit_state
    if not status_text:
        return None
    if any(token in status_text for token in ("cancel", "abort", "delete", "deleted")):
        return "cancelled"
    if any(token in status_text for token in ("fail", "error")):
        return "failed"
    if "complete" in status_text:
        return "completed"
    return None


def _update_pending_live_metadata(info, item=None, status=None):
    if not isinstance(info, dict):
        return
    if item:
        item_status = status if status is not None else item.get("status")
        if item_status:
            info["last_seen_status"] = str(item_status)
        item_path = str(item.get("path") or "").strip()
        if item_path:
            info["last_seen_path"] = item_path
    elif status:
        info["last_seen_status"] = str(status)


def _set_pending_stuck(info, reason, live_item=None):
    if not isinstance(info, dict):
        return
    info["state"] = "stuck"
    info["state_reason"] = str(reason or "waiting for action").strip() or "waiting for action"
    _update_pending_live_metadata(info, item=live_item, status="stuck")


def _clear_pending_stuck(info):
    if not isinstance(info, dict):
        return
    if str(info.get("state") or "").strip().lower() == "stuck":
        info["state"] = "queued"
    info["state_reason"] = None


def _serialize_downloads_state_locked():
    pending = {}
    for key, info in (_state.get("pending") or {}).items():
        if isinstance(info, dict):
            pending[str(key)] = dict(info)
    duplicates = _state.get("duplicates") or []
    if not isinstance(duplicates, list):
        duplicates = []
    return {
        "running": False,
        "last_run": float(_state.get("last_run") or 0.0),
        "pending": pending,
        "completed": sorted(str(item) for item in (_state.get("completed") or set())),
        "completed_identities": [
            [str(identity[0]), str(identity[1]), str(identity[2])]
            for identity in (_state.get("completed_identities") or set())
            if isinstance(identity, (tuple, list)) and len(identity) == 3
        ],
        "duplicates": [dict(entry) for entry in duplicates if isinstance(entry, dict)],
    }


def _persist_downloads_state_locked():
    try:
        os.makedirs(os.path.dirname(_DOWNLOADS_STATE_FILE), exist_ok=True)
        serialized = _serialize_downloads_state_locked()
        tmp_file = f"{_DOWNLOADS_STATE_FILE}.tmp"
        with open(tmp_file, "w", encoding="utf-8") as handle:
            json.dump(serialized, handle, ensure_ascii=True, indent=2, sort_keys=True)
        os.replace(tmp_file, _DOWNLOADS_STATE_FILE)
    except Exception as exc:
        logger.warning("Failed to persist downloads state: %s", exc)


def _persist_downloads_state():
    with _state_lock:
        _persist_downloads_state_locked()


def _load_downloads_state_locked():
    global _state_loaded
    if _state_loaded:
        return
    try:
        if os.path.exists(_DOWNLOADS_STATE_FILE):
            with open(_DOWNLOADS_STATE_FILE, "r", encoding="utf-8") as handle:
                raw = json.load(handle) or {}
            pending = raw.get("pending") if isinstance(raw, dict) else {}
            completed = raw.get("completed") if isinstance(raw, dict) else []
            completed_identities = raw.get("completed_identities") if isinstance(raw, dict) else []
            duplicates = raw.get("duplicates") if isinstance(raw, dict) else []
            _state["pending"] = pending if isinstance(pending, dict) else {}
            _state["completed"] = set(completed or [])
            restored_identities = set()
            for identity in completed_identities or []:
                if isinstance(identity, (tuple, list)) and len(identity) == 3:
                    restored_identities.add((str(identity[0]), str(identity[1]), str(identity[2])))
            _state["completed_identities"] = restored_identities
            if isinstance(duplicates, list):
                _state["duplicates"] = [dict(entry) for entry in duplicates if isinstance(entry, dict)][-200:]
            else:
                _state["duplicates"] = []
            try:
                _state["last_run"] = float(raw.get("last_run") or 0.0)
            except Exception:
                _state["last_run"] = 0.0
    except Exception as exc:
        logger.warning("Failed to load downloads state: %s", exc)
        _state["pending"] = {}
        _state["completed"] = set()
        _state["completed_identities"] = set()
        _state["duplicates"] = []
    _state_loaded = True
    return


def _ensure_downloads_state_loaded():
    with _state_lock:
        _load_downloads_state_locked()


def _get_snapshot_protocol_bucket(snapshot, protocol, bucket_name):
    return ((snapshot.get(bucket_name) or {}).get(protocol) or {})


def _get_snapshot_matches(info, snapshot):
    protocol = str((info or {}).get("protocol") or "").strip().lower()
    active_items = _get_snapshot_protocol_bucket(snapshot, protocol, "active_by_protocol").get("items") or []
    completed_items = _get_snapshot_protocol_bucket(snapshot, protocol, "completed_by_protocol").get("items") or []
    return {
        "protocol": protocol,
        "active_match": _match_completed_item(info, active_items),
        "completed_match": _match_completed_item(info, completed_items),
    }


def _get_unique_candidate_paths(*candidates):
    candidate_paths = []
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text and text not in candidate_paths:
            candidate_paths.append(text)
    return candidate_paths


def _build_pending_queue_item(key, info, snapshot):
    matches = _get_snapshot_matches(info, snapshot)
    active_match = matches["active_match"]
    completed_match = matches["completed_match"]
    state = "queued"
    state_reason = None
    if active_match:
        _clear_pending_stuck(info)
        _update_pending_live_metadata(info, item=active_match)
        state = _normalize_queue_state_label(active_match.get("status"))
        info["state"] = state
        info["state_reason"] = None
    elif str(info.get("state") or "").strip().lower() == "stuck":
        state = "stuck"
        state_reason = str(info.get("state_reason") or "").strip() or "waiting for action"
    elif completed_match:
        state = _normalize_terminal_queue_state(completed_match) or "completed"
        state_reason = str(completed_match.get("state_reason") or "").strip() or None
        _update_pending_live_metadata(info, item=completed_match, status=state)
        info["state"] = state
        info["state_reason"] = state_reason
    else:
        remembered_state = _normalize_terminal_queue_state(info)
        if remembered_state in ("failed", "cancelled"):
            state = remembered_state
            state_reason = str(info.get("state_reason") or "").strip() or None
    expected_name = str(info.get("expected_name") or "").strip()
    return {
        "key": key,
        "title_id": info.get("title_id"),
        "app_id": info.get("app_id"),
        "app_type": info.get("app_type"),
        "version": info.get("version"),
        "expected_name": expected_name or None,
        "hash": info.get("hash"),
        "id": info.get("id"),
        "protocol": info.get("protocol"),
        "client_type": info.get("client_type"),
        "label": _format_pending_display_label(
            info,
            state=state,
            active_match=active_match,
            completed_match=completed_match,
        ),
        "state": state,
        "state_reason": state_reason,
        "deletable": True,
    }


def _remove_pending_state_entry_locked(key):
    _state["pending"].pop(key, None)
    _state["completed"].discard(key)
    _persist_downloads_state_locked()


def _set_pending_stuck_by_key(key, reason, live_item=None):
    with _state_lock:
        live_info = _state["pending"].get(key)
        if live_info:
            _set_pending_stuck(live_info, reason, live_item=live_item)


def _delete_pending_payload_paths(candidate_paths):
    for path in candidate_paths:
        delete_ok, delete_message = _delete_download_payload(path)
        if not delete_ok:
            return False, delete_message or f"failed to delete {path}"
    return True, None


def _build_pending_delete_context(info, downloads, snapshot):
    matches = _get_snapshot_matches(info, snapshot)
    protocol = matches["protocol"]
    active_bucket = _get_snapshot_protocol_bucket(snapshot, protocol, "active_by_protocol")
    completed_bucket = _get_snapshot_protocol_bucket(snapshot, protocol, "completed_by_protocol")
    live_match = matches["active_match"] or matches["completed_match"]
    return {
        "protocol": protocol,
        "protocol_errors": ((snapshot.get("errors_by_protocol") or {}).get(protocol) or []),
        "active_bucket": active_bucket,
        "completed_bucket": completed_bucket,
        "active_match": matches["active_match"],
        "completed_match": matches["completed_match"],
        "live_match": live_match,
        "item_id": (
            (live_match or {}).get("id")
            or (live_match or {}).get("hash")
            or info.get("id")
            or info.get("hash")
        ),
        "candidate_paths": _get_unique_candidate_paths(
            (live_match or {}).get("path"),
            info.get("last_seen_path"),
        ),
        "client_configured": _is_protocol_client_configured(downloads, protocol),
        "client_cfg": (
            active_bucket.get("client_cfg")
            or completed_bucket.get("client_cfg")
            or _get_protocol_client_cfg(downloads, protocol)
        ),
    }


def _remove_stale_pending_download(key, delete_context):
    if delete_context["protocol_errors"] and delete_context["client_configured"]:
        failure_reason = "could not verify downloader state"
        _set_pending_stuck_by_key(key, f"delete failed: {failure_reason}")
        return False, f"Failed to remove queued download: {failure_reason}"

    payload_ok, payload_failure = _delete_pending_payload_paths(delete_context["candidate_paths"])
    if payload_ok:
        with _state_lock:
            _remove_pending_state_entry_locked(key)
        return True, "Removed stale queue entry."

    _set_pending_stuck_by_key(key, f"delete failed: {payload_failure or 'cleanup failed'}")
    return False, f"Failed to remove queued download: {payload_failure or 'cleanup failed'}"


def _remove_pending_live_downloader_item(delete_context):
    live_match = delete_context["live_match"]
    protocol = delete_context["protocol"]
    item_id = delete_context["item_id"]
    client_cfg = delete_context["client_cfg"]
    if live_match or delete_context["client_configured"]:
        if delete_context["active_match"] and item_id:
            return remove_active_download(protocol, client_cfg, item_id, delete_files=True)
        if delete_context["completed_match"] and item_id:
            return remove_completed_download(protocol, client_cfg, item_id, delete_files=True)
        if protocol == "torrent" and item_id:
            return remove_active_download(protocol, client_cfg, item_id, delete_files=True)
        return True, "No matching downloader item found."
    return False, "download client is not configured"


def _remove_pending_live_download(key, delete_context):
    downloader_ok, downloader_message = _remove_pending_live_downloader_item(delete_context)
    payload_ok = True
    payload_failure = None
    if downloader_ok:
        payload_ok, payload_failure = _delete_pending_payload_paths(delete_context["candidate_paths"])

    if downloader_ok and payload_ok:
        with _state_lock:
            _remove_pending_state_entry_locked(key)
        return True, "Removed queued download."

    failure_reason = downloader_message if not downloader_ok else payload_failure
    _set_pending_stuck_by_key(
        key,
        f"delete failed: {failure_reason or 'cleanup failed'}",
        live_item=delete_context["live_match"],
    )
    return False, f"Failed to remove queued download: {failure_reason or 'cleanup failed'}"


def get_downloads_state():
    _ensure_downloads_state_loaded()
    settings = load_settings()
    downloads = settings.get("downloads", {})
    snapshot = _get_download_activity_snapshot(downloads)
    _restore_pending_from_active(downloads, snapshot=snapshot)
    _reconcile_missing_pending_downloads(downloads, snapshot)
    with _state_lock:
        pending_items = []
        for key, info in _state["pending"].items():
            pending_items.append(_build_pending_queue_item(key, info, snapshot))
        return {
            "running": _state["running"],
            "last_run": _state["last_run"],
            "pending": pending_items,
            "completed": sorted(_state["completed"]),
            "duplicates": list(_state.get("duplicates") or []),
            "warnings": _get_download_capability_warnings(downloads),
        }


def _format_pending_label(info):
    title_id = str((info or {}).get("title_id") or "").strip().upper()
    version = (info or {}).get("version")
    if title_id and version is not None:
        return f"{title_id} v{version}"
    if title_id:
        return title_id
    if version is not None:
        return f"v{version}"
    expected_name = str((info or {}).get("expected_name") or "").strip()
    if expected_name:
        return expected_name
    title_name = str((info or {}).get("title_name") or "").strip()
    if title_name:
        return title_name
    return "Manual download"


def _format_pending_display_label(info, state="queued", active_match=None, completed_match=None):
    if not active_match or state in ("stuck", "completed", "failed", "cancelled"):
        for item in (completed_match, active_match):
            name = str((item or {}).get("name") or "").strip()
            if name:
                return name
        expected_name = str((info or {}).get("expected_name") or "").strip()
        if expected_name:
            return expected_name
    return _format_pending_label(info)


def run_downloads_job(scan_cb=None, post_cb=None):
    _ensure_downloads_state_loaded()
    settings = load_settings()
    downloads = settings.get("downloads", {})
    if not downloads.get("enabled"):
        with _state_lock:
            has_pending = bool(_state["pending"])
        if has_pending:
            _check_completed(downloads, scan_cb=scan_cb, post_cb=post_cb)
        return

    interval_minutes = int(downloads.get("interval_minutes") or 60)
    min_interval = max(interval_minutes, 5) * 60
    now = time.time()

    with _state_lock:
        if _state["running"]:
            return
        if _state["last_run"] and (now - _state["last_run"]) < min_interval:
            return
        _state["running"] = True
        _state["last_run"] = now

    try:
        _process_downloads(downloads, scan_cb=scan_cb, post_cb=post_cb)
    finally:
        with _state_lock:
            _state["running"] = False


def check_completed_downloads(scan_cb=None, post_cb=None):
    _ensure_downloads_state_loaded()
    settings = load_settings()
    downloads = settings.get("downloads", {})
    if not _get_completed_poll_targets(downloads):
        return False, "No download client is configured."
    _check_completed(downloads, scan_cb=scan_cb, post_cb=post_cb)
    return True, "Checked completed downloads."


def get_active_downloads():
    settings = load_settings()
    downloads = settings.get("downloads", {})
    targets = _get_completed_poll_targets(downloads)
    if not targets:
        return False, "No download client is configured.", [], {"down_speed": 0}
    try:
        items = []
        for protocol, client_cfg in targets:
            items.extend(list_active_downloads(protocol, client_cfg))
        items.sort(key=lambda item: ((item.get("protocol") or ""), (item.get("name") or "").lower()))
        down_speed = 0
        seen_queue_speed_keys = set()
        for item in items:
            down_speed += int(item.get("down_speed") or 0)
            queue_down_speed = int(item.get("queue_down_speed") or 0)
            if queue_down_speed > 0:
                queue_key = (
                    item.get("protocol") or "",
                    item.get("client_type") or "",
                )
                if queue_key not in seen_queue_speed_keys:
                    down_speed += queue_down_speed
                    seen_queue_speed_keys.add(queue_key)
        return True, None, items, {"down_speed": down_speed}
    except Exception as e:
        return False, str(e), [], {"down_speed": 0}


def _delete_download_payload(path):
    target = str(path or "").strip()
    if not target:
        return True, None
    if not os.path.exists(target):
        return True, None
    try:
        if os.path.isdir(target):
            shutil.rmtree(target)
        else:
            os.remove(target)
    except Exception as exc:
        return False, str(exc)
    return (not os.path.exists(target)), None if not os.path.exists(target) else "path still exists after deletion"


def remove_pending_download(key):
    key = str(key or "").strip()
    if not key:
        return False, "Missing queue key."

    _ensure_downloads_state_loaded()
    settings = load_settings()
    downloads = settings.get("downloads", {})
    _restore_pending_from_active(downloads)
    with _state_lock:
        info = dict((_state.get("pending") or {}).get(key) or {})
    if not info:
        return False, "Queue item not found."

    protocol = str(info.get("protocol") or "").strip().lower()
    if not protocol:
        _set_pending_stuck_by_key(key, "missing download protocol")
        return False, "Queue item is missing a download protocol."

    snapshot = _get_download_activity_snapshot(downloads)
    delete_context = _build_pending_delete_context(info, downloads, snapshot)
    if not delete_context["live_match"]:
        return _remove_stale_pending_download(key, delete_context)
    return _remove_pending_live_download(key, delete_context)


def remove_duplicate_download(duplicate_id):
    duplicate_id = str(duplicate_id or "").strip()
    if not duplicate_id:
        return False, "Missing duplicate key."

    _ensure_downloads_state_loaded()
    with _state_lock:
        duplicates = _state.get("duplicates")
        if not isinstance(duplicates, list):
            duplicates = []
            _state["duplicates"] = duplicates

        target_index = -1
        target_entry = None
        for index in range(len(duplicates) - 1, -1, -1):
            entry = duplicates[index]
            if not isinstance(entry, dict):
                continue
            if str(entry.get("id") or "").strip() == duplicate_id:
                target_index = index
                target_entry = dict(entry)
                break

    if target_index < 0 or not target_entry:
        return False, "Duplicate entry not found."

    target_path = str(target_entry.get("path") or "").strip()
    if not target_path:
        return False, "Duplicate entry has no deletable path."

    delete_ok, delete_message = _delete_download_payload(target_path)
    if not delete_ok:
        return False, f"Failed to delete duplicate file: {delete_message or 'cleanup failed'}"

    with _state_lock:
        duplicates = _state.get("duplicates")
        if not isinstance(duplicates, list):
            duplicates = []
            _state["duplicates"] = duplicates
        for index in range(len(duplicates) - 1, -1, -1):
            entry = duplicates[index]
            if not isinstance(entry, dict):
                continue
            if str(entry.get("id") or "").strip() == duplicate_id:
                duplicates.pop(index)
                _persist_downloads_state_locked()
                break
    return True, "Deleted rejected duplicate file."


def dismiss_duplicate_download(duplicate_id, fingerprint=None):
    duplicate_id = str(duplicate_id or "").strip()
    fingerprint = fingerprint if isinstance(fingerprint, dict) else {}
    if not duplicate_id and not fingerprint:
        return False, "Missing duplicate key."

    _ensure_downloads_state_loaded()
    with _state_lock:
        duplicates = _state.get("duplicates")
        if not isinstance(duplicates, list):
            duplicates = []
            _state["duplicates"] = duplicates

        for index in range(len(duplicates) - 1, -1, -1):
            entry = duplicates[index]
            if not isinstance(entry, dict):
                continue
            entry_id = str(entry.get("id") or "").strip()
            id_matches = bool(duplicate_id and entry_id == duplicate_id)
            fingerprint_matches = (
                not duplicate_id
                and str(entry.get("timestamp") or "") == str(fingerprint.get("timestamp") or "")
                and str(entry.get("label") or "") == str(fingerprint.get("label") or "")
                and str(entry.get("reason") or "") == str(fingerprint.get("reason") or "")
                and str(entry.get("protocol") or "") == str(fingerprint.get("protocol") or "")
            )
            if id_matches or fingerprint_matches:
                duplicates.pop(index)
                _persist_downloads_state_locked()
                return True, "Removed duplicate entry."
    return False, "Duplicate entry not found."


def _process_downloads(downloads, scan_cb=None, post_cb=None):
    prowlarr_cfg = downloads.get("prowlarr", {})
    if not prowlarr_cfg.get("url") or not prowlarr_cfg.get("api_key"):
        logger.warning("Downloads enabled, but Prowlarr is not configured.")
        return
    allowed_protocols = _get_configured_protocols(downloads)
    if not allowed_protocols:
        logger.warning("Downloads enabled, but no download client is configured.")
        return

    # Restore work which was queued before an AeroFoil restart before deciding
    # which updates still need searching.  This prevents a second NZB for an
    # update that is already in the downloader from being submitted.
    snapshot = _get_download_activity_snapshot(downloads)
    _restore_pending_from_active(downloads, snapshot=snapshot)
    _reconcile_missing_pending_downloads(downloads, snapshot)

    missing_updates = _get_missing_updates()
    if not missing_updates:
        _check_completed(downloads, scan_cb=scan_cb, post_cb=post_cb)
        return

    timeout_seconds = _get_prowlarr_timeout_seconds(prowlarr_cfg)
    search_limit = _get_prowlarr_search_limit(prowlarr_cfg)
    client = ProwlarrClient(prowlarr_cfg["url"], prowlarr_cfg["api_key"], timeout_seconds=timeout_seconds)
    indexer_ids = prowlarr_cfg.get("indexer_ids") or []
    categories = prowlarr_cfg.get("categories") or []
    required_terms = downloads.get("required_terms") or []
    required_terms_match = downloads.get("required_terms_match") or "all"
    blacklist_terms = downloads.get("blacklist_terms") or []
    min_seeders = _get_torrent_min_seeders(downloads)
    min_age_minutes = _get_usenet_min_age_minutes(downloads)

    for update in missing_updates:
        _search_and_queue(
            client=client,
            update=update,
            downloads=downloads,
            indexer_ids=indexer_ids,
            categories=categories,
            required_terms=required_terms,
            required_terms_match=required_terms_match,
            blacklist_terms=blacklist_terms,
            min_seeders=min_seeders,
            min_age_minutes=min_age_minutes,
            search_limit=search_limit,
            allow_duplicates=False,
            allowed_protocols=allowed_protocols,
        )

    _check_completed(downloads, scan_cb=scan_cb, post_cb=post_cb)


def manual_search_update(title_id, version):
    settings = load_settings()
    downloads = settings.get("downloads", {})
    prowlarr_cfg = downloads.get("prowlarr", {})
    allowed_protocols = _get_configured_protocols(downloads)
    if not prowlarr_cfg.get("url") or not prowlarr_cfg.get("api_key"):
        return False, "Prowlarr is not configured."
    if not allowed_protocols:
        return False, "No download client is configured."

    title_name = title_id
    titles_lib.load_titledb()
    try:
        info = titles_lib.get_game_info(title_id) or {}
        title_name = info.get("name") or title_id
    finally:
        titles_lib.release_titledb()

    update = {
        "title_id": title_id,
        "title_name": title_name,
        "version": int(version),
    }
    timeout_seconds = _get_prowlarr_timeout_seconds(prowlarr_cfg)
    search_limit = _get_prowlarr_search_limit(prowlarr_cfg)
    client = ProwlarrClient(prowlarr_cfg["url"], prowlarr_cfg["api_key"], timeout_seconds=timeout_seconds)
    ok, message = _search_and_queue(
        client=client,
        update=update,
        downloads=downloads,
        indexer_ids=prowlarr_cfg.get("indexer_ids") or [],
        categories=prowlarr_cfg.get("categories") or [],
        required_terms=downloads.get("required_terms") or [],
        required_terms_match=downloads.get("required_terms_match") or "all",
        blacklist_terms=downloads.get("blacklist_terms") or [],
        min_seeders=_get_torrent_min_seeders(downloads),
        min_age_minutes=_get_usenet_min_age_minutes(downloads),
        search_limit=search_limit,
        allow_duplicates=False,
        allowed_protocols=allowed_protocols,
        require_exact_version=False,
    )
    return ok, message


def search_update_options(title_id, version, limit=20):
    settings = load_settings()
    downloads = settings.get("downloads", {})
    prowlarr_cfg = downloads.get("prowlarr", {})
    # Listing options only needs Prowlarr; a download client is required to
    # queue, and queue_download_url reports that clearly at that point. With
    # no client configured the protocol filter simply is not applied.
    allowed_protocols = _get_configured_protocols(downloads)
    if not prowlarr_cfg.get("url") or not prowlarr_cfg.get("api_key"):
        return False, "Prowlarr is not configured.", []

    title_name = title_id
    titles_lib.load_titledb()
    try:
        info = titles_lib.get_game_info(title_id) or {}
        title_name = info.get("name") or title_id
    finally:
        titles_lib.release_titledb()

    update = {
        "title_id": title_id,
        "title_name": title_name,
        "version": int(version),
    }
    query_candidates = _build_queries(update)
    timeout_seconds = _get_prowlarr_timeout_seconds(prowlarr_cfg)
    search_limit = _get_prowlarr_search_limit(prowlarr_cfg)
    client = ProwlarrClient(prowlarr_cfg["url"], prowlarr_cfg["api_key"], timeout_seconds=timeout_seconds)
    results = []
    categories = prowlarr_cfg.get("categories") or []
    min_seeders = _get_torrent_min_seeders(downloads)
    min_age_minutes = _get_usenet_min_age_minutes(downloads)
    for query in query_candidates:
        results = client.search(
            query,
            indexer_ids=prowlarr_cfg.get("indexer_ids") or [],
            categories=categories,
            limit=search_limit,
        )
        results = [
            item for item in (results or [])
            if pick_best_result(
                [item],
                title_id=update["title_id"],
                version=update["version"],
                min_seeders=min_seeders,
                min_age_minutes=min_age_minutes,
                required_terms=downloads.get("required_terms") or [],
                required_terms_match=downloads.get("required_terms_match") or "all",
                blacklist_terms=downloads.get("blacklist_terms") or [],
                allowed_protocols=allowed_protocols,
                require_exact_version=True,
            ) is not None
        ]
        if results:
            break
    trimmed = [
        {
            "title": r.get("title"),
            "indexer": r.get("indexer"),
            "size": r.get("size"),
            "seeders": r.get("seeders"),
            "leechers": r.get("leechers"),
            "download_url": r.get("download_url"),
            "protocol": r.get("protocol"),
            "age_minutes": r.get("age_minutes"),
            "age_label": r.get("age_label"),
            "published_at": r.get("published_at"),
        }
        for r in sort_download_search_results(results)[:limit]
    ]
    return True, None, trimmed


def queue_download_url(download_url, expected_name=None, update_only=False, dlc_only=False, expected_version=None, title_id=None, protocol=None):
    settings = load_settings()
    downloads = settings.get("downloads", {})
    resolved_protocol = _infer_protocol(download_url=download_url, explicit_protocol=protocol)
    if not resolved_protocol:
        return False, "Unable to determine download protocol."
    client_cfg = _get_protocol_client_cfg(downloads, resolved_protocol)
    if not _is_protocol_client_configured(downloads, resolved_protocol):
        return False, f"No {resolved_protocol} client is configured."
    if update_only and title_id and expected_version is not None:
        try:
            requested_version = int(expected_version)
        except (TypeError, ValueError):
            requested_version = None
        if requested_version is not None:
            known_highest = _get_known_update_version(title_id)
            if known_highest >= requested_version:
                return False, f"duplicate update: {str(title_id).strip().upper()} v{requested_version} already known (latest v{known_highest})"
    queue_update_only = bool(update_only and resolved_protocol != "usenet")
    queue_dlc_only = bool(dlc_only)
    ok, message, item_id = queue_download(
        resolved_protocol,
        client_cfg,
        download_url,
        expected_name=expected_name,
        update_only=queue_update_only,
        dlc_only=queue_dlc_only,
        exclude_russian=True,
        expected_version=expected_version,
    )
    if ok:
        tracked_title_id = None
        tracked_version = None
        if update_only and title_id and expected_version is not None:
            try:
                tracked_version = int(expected_version)
            except (TypeError, ValueError):
                tracked_version = None
            tracked_title_id = str(title_id).strip().upper() or None
        key = f"manual:{int(time.time())}"
        update = {
            "title_id": tracked_title_id,
            "title_name": expected_name or tracked_title_id or "Manual download",
            "version": tracked_version,
        }
        _track_pending(
            key,
            update,
            item_id,
            expected_name=expected_name,
            protocol=resolved_protocol,
            client_type=client_cfg.get("type"),
        )
        return True, "Queued download."
    return False, message


def _search_and_queue(
    client,
    update,
    downloads,
    indexer_ids,
    categories,
    required_terms,
    blacklist_terms,
    min_seeders,
    min_age_minutes,
    search_limit,
    required_terms_match="all",
    allow_duplicates=True,
    allowed_protocols=None,
    require_exact_version=True,
):
    key = f"{update['title_id']}:{update['version']}"
    if not allow_duplicates and _already_tracked(key, update=update):
        return False, "Update is already queued."
    try:
        requested_version = int(update.get("version"))
    except (TypeError, ValueError):
        requested_version = None
    if requested_version is not None:
        known_highest = _get_known_update_version(update["title_id"])
        if known_highest >= requested_version:
            return False, f"duplicate update: {update['title_id']} v{requested_version} already known (latest v{known_highest})"

    query_candidates = _build_queries(update)
    result = None
    for query in query_candidates:
        results = client.search(query, indexer_ids=indexer_ids, categories=categories, limit=search_limit)
        result = pick_best_result(
            results,
            title_id=update["title_id"],
            version=update["version"],
            min_seeders=min_seeders,
            min_age_minutes=min_age_minutes,
            required_terms=required_terms,
            required_terms_match=required_terms_match,
            blacklist_terms=blacklist_terms,
            allowed_protocols=allowed_protocols,
            require_exact_version=require_exact_version,
        )
        if result:
            break
    if not result:
        return False, "No matching results found."

    protocol = _infer_protocol(
        download_url=result.get("download_url"),
        explicit_protocol=result.get("protocol"),
    )
    if protocol not in (allowed_protocols or []):
        return False, f"No {protocol or 'matching'} client is configured."

    download_url = result.get("download_url")
    if not download_url:
        return False, "Missing download URL."

    client_cfg = _get_protocol_client_cfg(downloads, protocol)
    ok, message, item_id = queue_download(
        protocol,
        client_cfg,
        download_url,
        expected_name=update.get("search_terms") or result.get("title"),
        update_only=True,
        exclude_russian=True,
        expected_version=update.get("version"),
    )
    if ok:
        _track_pending(
            key,
            update,
            item_id,
            expected_name=result.get("title"),
            protocol=protocol,
            client_type=client_cfg.get("type"),
        )
        logger.info(
            "Queued %s update %s v%s: %s",
            protocol,
            update["title_id"],
            update["version"],
            result.get("title"),
        )
        return True, "Queued download."
    return False, message


def _build_queries(update):
    title_name = update.get("title_name") or update["title_id"]
    downloads = load_settings().get("downloads", {})

    def _apply_char_replacements(text):
        out = str(text or "")
        for rule in downloads.get("search_char_replacements") or []:
            if not isinstance(rule, dict):
                continue
            from_text = str(rule.get("from") or "")
            to_text = str(rule.get("to") or "")
            if not from_text:
                continue
            out = out.replace(from_text, to_text)
        return out

    def _normalize_query(text):
        if not text:
            return ""
        text = _apply_char_replacements(text)
        try:
            normalized = unicodedata.normalize("NFKD", text)
            normalized = normalized.encode("ascii", "ignore").decode("ascii")
        except Exception:
            normalized = text
        normalized = re.sub(r"[^A-Za-z0-9\s]+", " ", normalized)
        return re.sub(r"\s+", " ", normalized).strip()

    title_name = _normalize_query(title_name)
    prefix = _normalize_query(downloads.get("search_prefix") or "")
    suffix = _normalize_query(downloads.get("search_suffix") or "")
    base = f"{prefix} {title_name}".strip() if prefix else title_name
    tail = f" {suffix}".strip() if suffix else ""
    update["search_terms"] = title_name
    return [
        f"{base}{tail}".strip(),
        f"{title_name} update",
    ]


def _get_missing_updates():
    titles_lib.load_titledb()
    try:
        titles = get_all_titles()
        missing = []
        for title in titles:
            if not title.have_base:
                continue
            title_id = title.title_id
            title_info = titles_lib.get_game_info(title_id) or {}
            title_name = title_info.get("name") or title_id
            versions = titles_lib.get_all_existing_versions(title_id) or []
            owned_updates = [
                app for app in get_all_title_apps(title_id)
                if app.get("app_type") == APP_TYPE_UPD and app.get("owned")
            ]
            owned_versions = {
                int(app.get("app_version") or 0) for app in owned_updates
                if app.get("app_version") is not None
            }
            available_versions = [
                int(version_info.get("version") or 0)
                for version_info in versions
                if int(version_info.get("version") or 0) > 0
            ]
            if not available_versions:
                continue
            highest_available = max(available_versions)
            highest_owned = max(owned_versions) if owned_versions else 0
            if highest_owned >= highest_available:
                continue
            missing.append({
                "title_id": title_id,
                "title_name": title_name,
                "version": highest_available,
            })
        return missing
    finally:
        titles_lib.release_titledb()


def _already_tracked(key, update=None):
    _ensure_downloads_state_loaded()
    with _state_lock:
        if key in _state["pending"] or key in _state["completed"]:
            return True
        if not isinstance(update, dict):
            return False
        title_id = str(update.get("title_id") or "").strip().upper()
        try:
            version = int(update.get("version"))
        except (TypeError, ValueError):
            return False
        title_name = _normalize_match_text(update.get("title_name"))
        for info in _state["pending"].values():
            if not isinstance(info, dict):
                continue
            if (
                str(info.get("title_id") or "").strip().upper() == title_id
                and str(info.get("version") or "").strip() == str(version)
            ):
                return True
            # Restored downloader items may not have a readable payload yet,
            # so use their release name as a conservative fallback.
            label = _normalize_match_text(info.get("expected_name") or info.get("title_name"))
            label_version = _extract_update_version_from_name(label)
            if title_name and title_name in label and (label_version is None or label_version == version):
                return True
        return False


def _normalize_pending_item_id(item_id, protocol=None):
    text = str(item_id or "").strip()
    if not text:
        return ""
    if str(protocol or "").strip().lower() == "torrent":
        return text.lower()
    return text


def _get_pending_identity(info):
    protocol = str((info or {}).get("protocol") or "").strip().lower()
    client_type = str((info or {}).get("client_type") or "").strip().lower()
    item_id = _normalize_pending_item_id((info or {}).get("id") or (info or {}).get("hash"), protocol=protocol)
    if item_id:
        return protocol, client_type, item_id
    expected_name = _normalize_match_text((info or {}).get("expected_name") or (info or {}).get("title_name"))
    if expected_name:
        return protocol, client_type, expected_name
    return None


def _get_completed_identities_locked():
    identities = _state.get("completed_identities")
    if isinstance(identities, set):
        return identities
    identities = set(identities or [])
    _state["completed_identities"] = identities
    return identities


def _build_restored_pending_key(item):
    protocol = str((item or {}).get("protocol") or "").strip().lower() or "download"
    client_type = str((item or {}).get("client_type") or "").strip().lower() or "client"
    item_id = _normalize_pending_item_id((item or {}).get("id") or (item or {}).get("hash"), protocol=protocol)
    if item_id:
        return f"restored:{protocol}:{client_type}:{item_id}"
    label = _normalize_match_text((item or {}).get("name")) or "unknown"
    return f"restored:{protocol}:{client_type}:name:{label}"

def _infer_content_info_from_completed_item(item):
    src_path = str((item or {}).get("path") or "").strip()
    if not src_path:
        return None

    candidates = []
    for path in _iter_importable_download_files(src_path):
        try:
            _, success, contents, _ = titles_lib.identify_file(path)
        except Exception:
            success = False
            contents = []
        if not success or not contents:
            normalized_name = os.path.basename(path)
            normalized_extension = _get_import_extension(path)
            if normalized_extension and normalized_name.lower().endswith(f".{normalized_extension}.hdf"):
                normalized_name = normalized_name[:-4]
            app_id, title_id, app_type, version, error = titles_lib.identify_file_from_filename(normalized_name)
            if not error and title_id and app_type:
                contents = [{
                    "title_id": title_id,
                    "app_id": app_id,
                    "type": app_type,
                    "version": version,
                }]
        for content in contents or []:
            title_id = str(content.get("title_id") or "").strip().upper() or None
            app_id = str(content.get("app_id") or "").strip().upper() or None
            app_type = str(content.get("type") or "").strip().upper() or None
            try:
                version = int(content.get("version")) if content.get("version") is not None else None
            except (TypeError, ValueError):
                version = None
            if not title_id and not app_id and not app_type:
                continue
            candidates.append({
                "title_id": title_id,
                "app_id": app_id,
                "app_type": app_type,
                "version": version,
            })

    if not candidates:
        inferred_update = _infer_update_info_from_completed_item(item)
        if not inferred_update:
            return None
        title_id = str(inferred_update.get("title_id") or "").strip().upper() or None
        return {
            "title_id": title_id,
            "app_id": (f"{title_id[:-3]}800" if title_id and len(title_id) == 16 else None),
            "app_type": APP_TYPE_UPD,
            "title_name": inferred_update.get("title_name"),
            "version": inferred_update.get("version"),
        }

    app_types = {entry["app_type"] for entry in candidates if entry.get("app_type")}
    title_ids = {entry["title_id"] for entry in candidates if entry.get("title_id")}
    app_ids = {entry["app_id"] for entry in candidates if entry.get("app_id")}
    versions = {entry["version"] for entry in candidates if entry.get("version") is not None}

    app_type = next(iter(app_types)) if len(app_types) == 1 else None
    title_id = next(iter(title_ids)) if len(title_ids) == 1 else None
    app_id = next(iter(app_ids)) if len(app_ids) == 1 else None
    version = next(iter(versions)) if len(versions) == 1 else None
    title_name = None

    lookup_ids = []
    if app_type == APP_TYPE_DLC and app_id:
        lookup_ids.append(app_id)
    if title_id:
        lookup_ids.append(title_id)
    for lookup_id in lookup_ids:
        try:
            title_info = titles_lib.get_game_info(lookup_id) or {}
        except Exception:
            title_info = {}
        title_name = str(title_info.get("name") or "").strip() or None
        if title_name:
            break

    return {
        "title_id": title_id,
        "app_id": app_id,
        "app_type": app_type,
        "title_name": title_name,
        "version": version,
    }


def _infer_pending_info_from_queue_item(item):
    item = item or {}
    name = str(item.get("name") or "").strip() or None
    protocol = str(item.get("protocol") or "").strip().lower() or None
    client_type = str(item.get("client_type") or "").strip().lower() or None
    normalized_id = _normalize_pending_item_id(item.get("id") or item.get("hash"), protocol=protocol)
    terminal_state = _normalize_terminal_queue_state(item)
    state_reason = str(item.get("state_reason") or "").strip() or None
    info = {
        "title_id": None,
        "app_id": None,
        "app_type": None,
        "version": None,
        "hash": normalized_id or None,
        "id": normalized_id or None,
        "expected_name": name,
        "title_name": name,
        "protocol": protocol,
        "client_type": client_type,
        "state": terminal_state or "queued",
        "state_reason": state_reason,
        "last_seen_status": item.get("status") or None,
        "last_seen_path": str(item.get("path") or "").strip() or None,
    }
    inferred = _infer_content_info_from_completed_item(item)
    if inferred:
        info["title_id"] = inferred.get("title_id")
        info["app_id"] = inferred.get("app_id")
        info["app_type"] = inferred.get("app_type")
        if inferred.get("app_type") != APP_TYPE_BASE:
            info["version"] = inferred.get("version")
        info["title_name"] = inferred.get("title_name") or info["title_name"]
    return info


def _restore_pending_from_active(downloads, snapshot=None):
    _ensure_downloads_state_loaded()
    poll_targets = _get_completed_poll_targets(downloads)
    if not poll_targets:
        return 0

    queued_items = []
    if isinstance(snapshot, dict):
        active_by_protocol = snapshot.get("active_by_protocol") or {}
        completed_by_protocol = snapshot.get("completed_by_protocol") or {}
        for protocol, _client_cfg in poll_targets:
            active_bucket = active_by_protocol.get(protocol) or {}
            queued_items.extend(list(active_bucket.get("items") or []))
            if protocol == "usenet":
                completed_bucket = completed_by_protocol.get(protocol) or {}
                queued_items.extend(list(completed_bucket.get("items") or []))
    else:
        for protocol, client_cfg in poll_targets:
            try:
                queued_items.extend(list_active_downloads(protocol, client_cfg))
            except Exception as exc:
                logger.warning("Failed to restore pending %s queue state: %s", protocol, exc)
            if protocol == "usenet":
                try:
                    queued_items.extend(list_history_downloads(protocol, client_cfg))
                except Exception as exc:
                    logger.warning("Failed to restore completed %s queue state: %s", protocol, exc)

    if not queued_items:
        return 0

    restored = 0
    with _state_lock:
        completed_identities = _get_completed_identities_locked()
        known_identities = {
            identity for identity in (_get_pending_identity(info) for info in _state["pending"].values())
            if identity
        }
        known_identities.update(completed_identities)
        for item in queued_items:
            identity = _get_pending_identity(item)
            if identity and identity in known_identities:
                continue
            key = _build_restored_pending_key(item)
            if key in _state["pending"] or key in _state["completed"]:
                if identity:
                    known_identities.add(identity)
                continue
            _state["pending"][key] = _infer_pending_info_from_queue_item(item)
            if identity:
                known_identities.add(identity)
            restored += 1
        if restored:
            _persist_downloads_state_locked()
    return restored


def _reconcile_missing_pending_downloads(downloads, snapshot):
    """Drop tracked jobs that have disappeared from a successfully polled client.

    A newly submitted NZB can take a moment to appear in SABnzbd, so an item
    must be absent for a short grace period before its local queue record is
    removed.  Poll errors are deliberately never treated as an empty queue.
    """
    if not isinstance(snapshot, dict):
        return 0
    now = time.time()
    removed = 0
    changed = False
    errors_by_protocol = snapshot.get("errors_by_protocol") or {}
    with _state_lock:
        for key, info in list(_state.get("pending", {}).items()):
            if not isinstance(info, dict):
                continue
            protocol = str(info.get("protocol") or "").strip().lower()
            if not protocol or errors_by_protocol.get(protocol):
                continue
            if not _is_protocol_client_configured(downloads, protocol):
                continue
            matches = _get_snapshot_matches(info, snapshot)
            if matches["active_match"] or matches["completed_match"]:
                if info.pop("missing_since", None) is not None:
                    changed = True
                continue
            try:
                missing_since = float(info.get("missing_since"))
            except (TypeError, ValueError):
                missing_since = 0.0
            if not missing_since:
                info["missing_since"] = now
                changed = True
                continue
            if now - missing_since >= _PENDING_MISSING_GRACE_SECONDS:
                _state["pending"].pop(key, None)
                _state["completed"].discard(key)
                removed += 1
                changed = True
                logger.info("Removed stale AeroFoil queue entry no longer present in %s: %s", protocol, key)
        if changed:
            _persist_downloads_state_locked()
    return removed


def _track_pending(key, update, item_id, expected_name=None, protocol=None, client_type=None):
    _ensure_downloads_state_loaded()
    normalized_id = _normalize_pending_item_id(item_id, protocol=protocol)
    with _state_lock:
        _state["pending"][key] = {
            "title_id": update["title_id"],
            "app_id": update.get("app_id"),
            "app_type": update.get("app_type"),
            "version": update["version"],
            "hash": normalized_id or None,
            "id": normalized_id or None,
            "expected_name": expected_name or update.get("title_name"),
            "title_name": update.get("title_name"),
            "protocol": protocol,
            "client_type": client_type,
            "state": "queued",
            "state_reason": None,
            "last_seen_status": None,
            "last_seen_path": None,
            "missing_since": None,
        }
        _persist_downloads_state_locked()


def _match_completed_item(info, completed_items):
    protocol = str((info or {}).get("protocol") or "").strip().lower()
    item_id = _normalize_pending_item_id((info or {}).get("id") or (info or {}).get("hash"), protocol=protocol)
    if item_id:
        match = next((
            item for item in completed_items
            if _normalize_pending_item_id(item.get("id") or item.get("hash"), protocol=protocol) == item_id
        ), None)
        if match:
            return match
    expected = (info.get("expected_name") or "").lower()
    if expected:
        return next((item for item in completed_items if expected in (item.get("name") or "").lower()), None)
    return None


def _resolve_completed_update_info(info, completed_item):
    if not isinstance(info, dict):
        return info
    title_id = str(info.get("title_id") or "").strip()
    version = info.get("version")
    if info.get("app_type") != APP_TYPE_BASE and title_id and version is not None:
        return info
    inferred = _infer_update_info_from_completed_item(completed_item)
    if not inferred:
        return info
    merged = dict(info)
    merged["app_type"] = APP_TYPE_UPD
    merged["title_id"] = inferred.get("title_id")
    merged["title_name"] = inferred.get("title_name") or merged.get("title_name")
    merged["version"] = inferred.get("version")
    return merged


def _normalize_match_text(text):
    return re.sub(r"[^a-z0-9]+", " ", str(text or "").lower()).strip()


def _iter_completed_files(src_path):
    if not src_path:
        return
    if os.path.isfile(src_path):
        yield src_path
        return
    if not os.path.isdir(src_path):
        return
    for root, _, files in os.walk(src_path):
        for filename in files:
            yield os.path.join(root, filename)


def _collect_completed_update_candidates(src_path):
    candidates = []
    for path in _iter_completed_files(src_path) or []:
        filename = os.path.basename(path)
        version = _extract_update_version_from_name(filename)
        # Archive releases can carry the same version markers as the extracted
        # Switch payload. Never let an archive become the update candidate:
        # it may be unpacked by a post-processing tool after the torrent has
        # completed, and only supported Switch media formats are safe to import.
        if version is None or not is_supported_content_path(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        candidates.append((version, size, path))
    candidates.sort(reverse=True)
    return candidates


def _select_completed_update_candidate(src_path):
    candidates = _collect_completed_update_candidates(src_path)
    if not candidates:
        return None, None
    version, _, path = candidates[0]
    return path, version


def _get_highest_owned_update_version(title_id):
    title_id = str(title_id or "").strip().upper()
    if not title_id:
        return 0
    owned_updates = [
        app for app in get_all_title_apps(title_id)
        if app.get("app_type") == APP_TYPE_UPD and app.get("owned")
    ]
    owned_versions = [
        int(app.get("app_version") or 0) for app in owned_updates
        if app.get("app_version") is not None
    ]
    return max(owned_versions) if owned_versions else 0


def _get_known_update_version(title_id):
    try:
        return max(
            _get_highest_owned_update_version(title_id),
            _get_local_known_update_version(title_id),
        )
    except Exception:
        return 0


def _should_remove_completed_torrent(client_cfg):
    cfg = client_cfg or {}
    return bool(cfg.get("remove_completed_torrents_on_finish", True))


def _build_completed_match_text(item):
    src_path = str((item or {}).get("path") or "").strip()
    parts = [str((item or {}).get("name") or "").strip(), os.path.basename(src_path)]
    for path in _iter_completed_files(src_path) or []:
        parts.append(os.path.basename(path))
    return _normalize_match_text(" ".join(part for part in parts if part))


def _infer_update_info_from_completed_item(item):
    src_path = str((item or {}).get("path") or "").strip()
    _, version = _select_completed_update_candidate(src_path)
    if not version:
        return None

    normalized_match_text = _build_completed_match_text(item)
    if not normalized_match_text:
        return None

    titles = get_all_titles() or []
    if not titles:
        return None

    titles_lib.load_titledb()
    try:
        candidates = []
        for title in titles:
            title_id = str(getattr(title, "title_id", "") or "").strip().upper()
            if not title_id:
                continue
            versions = titles_lib.get_all_existing_versions(title_id) or []
            if not any(int(v.get("version") or 0) == int(version) for v in versions):
                continue
            info = titles_lib.get_game_info(title_id) or {}
            title_name = str(info.get("name") or title_id).strip()
            normalized_title = _normalize_match_text(title_name)
            if not normalized_title or normalized_title not in normalized_match_text:
                continue
            candidates.append((len(normalized_title), title_id, title_name))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        _, title_id, title_name = candidates[0]
        return {
            "title_id": title_id,
            "title_name": title_name,
            "version": int(version),
        }
    finally:
        titles_lib.release_titledb()


def _adopt_untracked_completed_item(item):
    inferred = _infer_update_info_from_completed_item(item)
    if inferred:
        moved_path = _move_completed(item, inferred)
    elif _looks_like_update_download(item):
        protocol = str((item or {}).get("protocol") or "").strip().lower()
        client_type = str((item or {}).get("client_type") or "").strip().lower()
        if protocol == "usenet" or client_type == "sabnzbd":
            moved_path, move_reason = _move_completed_with_reason(item)
            if not moved_path:
                logger.warning(
                    "Failed generic import for untracked completed update-like %s download %s: %s",
                    protocol or client_type or "managed",
                    item.get("name") or item.get("path") or "",
                    move_reason or "unknown error",
                )
                return None
            logger.warning(
                "Adopted untracked completed update-like %s download with generic import because update inference failed: %s",
                protocol or client_type or "managed",
                item.get("name") or item.get("path") or "",
            )
        else:
            return None
    else:
        moved_path = _move_completed(item)
    if moved_path:
        if inferred:
            logger.info(
                "Adopted untracked completed download by category as %s v%s: %s",
                inferred.get("title_id"),
                inferred.get("version"),
                item.get("name") or item.get("path") or "",
            )
        else:
            logger.info(
                "Adopted untracked completed download by category without title mapping: %s",
                item.get("name") or item.get("path") or "",
            )
    return moved_path


def _coerce_moved_paths(moved_result):
    if not moved_result:
        return []
    if isinstance(moved_result, (list, tuple, set)):
        return [path for path in moved_result if path]
    return [moved_result]


def _looks_like_update_download(item):
    name = str((item or {}).get("name") or "").lower()
    if "update" in name:
        return True
    src_path = str((item or {}).get("path") or "").strip()
    update_path, version = _select_completed_update_candidate(src_path)
    return bool(update_path and version)


def _load_completed_download_buckets(poll_targets):
    completed_by_protocol = {}
    for protocol, client_cfg in poll_targets:
        completed_by_protocol[protocol] = {
            "client_cfg": client_cfg,
            "items": list_completed_downloads(protocol, client_cfg),
            "matched_ids": set(),
        }
    return completed_by_protocol


def _process_tracked_completed_item_locked(key, info, bucket):
    match = _match_completed_item(info, bucket["items"])
    if not match:
        return []

    _update_pending_live_metadata(info, item=match, status="completed")
    matched_id = match.get("id") or match.get("hash")
    if matched_id:
        bucket["matched_ids"].add(matched_id)
    move_info = _resolve_completed_update_info(info, match)
    retain_torrent = (
        str(info.get("protocol") or "").strip().lower() == "torrent"
        and not _should_remove_completed_torrent(bucket.get("client_cfg"))
    )
    if retain_torrent:
        moved_result, move_reason = _move_completed_with_reason(match, move_info, copy_files=True)
    else:
        moved_result, move_reason = _move_completed_with_reason(match, move_info)
    moved_match_paths = _coerce_moved_paths(moved_result)
    if not moved_match_paths:
        if _is_duplicate_reason(move_reason):
            _track_duplicate_locked(info, match, move_reason, key=key)
            _state["pending"].pop(key, None)
            _state["completed"].add(key)
            identity = _get_pending_identity(match) or _get_pending_identity(info)
            if identity:
                _get_completed_identities_locked().add(identity)
            if matched_id and not retain_torrent:
                ok, message = remove_completed_download(
                    str(info.get("protocol") or "").strip().lower(),
                    bucket["client_cfg"],
                    matched_id,
                )
                if not ok:
                    logger.warning("Failed to remove duplicate completed %s item %s: %s", info.get("protocol"), matched_id, message)
            return []
        logger.warning(
            "Matched completed download for pending key %s, but move failed. Keeping pending entry for retry: %s",
            key,
            move_reason or "unknown error",
        )
        _set_pending_stuck(info, move_reason or "move failed", live_item=match)
        return []

    _state["pending"].pop(key, None)
    _state["completed"].add(key)
    identity = _get_pending_identity(match) or _get_pending_identity(info)
    if identity:
        _get_completed_identities_locked().add(identity)
    if matched_id and not retain_torrent:
        ok, message = remove_completed_download(
            str(info.get("protocol") or "").strip().lower(),
            bucket["client_cfg"],
            matched_id,
        )
        if not ok:
            logger.warning("Failed to remove completed %s item %s: %s", info.get("protocol"), matched_id, message)
    return moved_match_paths


def _process_untracked_completed_bucket_locked(protocol, bucket):
    unmatched_count = 0
    moved_paths = []
    for item in bucket["items"]:
        item_id = item.get("id") or item.get("hash")
        if item_id and item_id in bucket["matched_ids"]:
            continue
        if protocol == "torrent":
            unmatched_count += 1
            continue
        moved_item_paths = _coerce_moved_paths(_adopt_untracked_completed_item(item))
        if moved_item_paths:
            matched_id = item.get("id") or item.get("hash")
            if matched_id and not (
                protocol == "torrent" and not _should_remove_completed_torrent(bucket.get("client_cfg"))
            ):
                ok, message = remove_completed_download(protocol, bucket["client_cfg"], matched_id)
                if not ok:
                    logger.warning("Failed to remove adopted %s item %s: %s", protocol, matched_id, message)
            moved_paths.extend(moved_item_paths)
            continue
        unmatched_count += 1
    return moved_paths, unmatched_count


def _check_completed(downloads, scan_cb=None, post_cb=None):
    _ensure_downloads_state_loaded()
    _restore_pending_from_active(downloads)
    poll_targets = _get_completed_poll_targets(downloads)
    if not poll_targets:
        return

    completed_by_protocol = _load_completed_download_buckets(poll_targets)
    if not any(bucket["items"] for bucket in completed_by_protocol.values()):
        logger.info("No completed downloads detected for configured clients.")
        return

    newly_completed = False
    moved_paths = []
    with _state_lock:
        for key, info in list(_state["pending"].items()):
            protocol = str(info.get("protocol") or "").strip().lower()
            bucket = completed_by_protocol.get(protocol)
            if not bucket:
                continue
            moved_match_paths = _process_tracked_completed_item_locked(key, info, bucket)
            if not moved_match_paths:
                continue
            moved_paths.extend(moved_match_paths)
            newly_completed = True
        _persist_downloads_state_locked()

        for protocol, bucket in completed_by_protocol.items():
            moved_item_paths, unmatched_count = _process_untracked_completed_bucket_locked(protocol, bucket)
            if moved_item_paths:
                moved_paths.extend(moved_item_paths)
                newly_completed = True
            if unmatched_count:
                logger.info(
                    "Ignored %s completed %s download(s) not tracked by AeroFoil pending state.",
                    unmatched_count,
                    protocol,
                )

    if newly_completed:
        if moved_paths:
            enqueue_organize_paths(moved_paths)
            enqueue_cleanup_roots([path for path in moved_paths if os.path.isdir(path)])
        if scan_cb:
            logger.info("New downloads completed. Scanning library.")
            scan_cb()
            if post_cb:
                post_cb()


def _extract_update_version_from_name(name):
    return extract_internal_update_version(name)


def _select_update_file_path(src_path, expected_version):
    if not src_path or not expected_version:
        return None
    try:
        expected_version = int(expected_version)
    except (TypeError, ValueError):
        return None
    if os.path.isfile(src_path):
        version = _extract_update_version_from_name(os.path.basename(src_path))
        return src_path if version == expected_version else None
    if not os.path.isdir(src_path):
        return None
    candidates = []
    for root, _, files in os.walk(src_path):
        for filename in files:
            version = _extract_update_version_from_name(filename)
            if version == expected_version:
                path = os.path.join(root, filename)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                candidates.append((size, path))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _build_update_destination(dest_root, title_id, app_id, title_name, version, src_path):
    safe_title = _sanitize_component(title_name or title_id)
    safe_title_id = _sanitize_component(title_id)
    safe_app_id = _sanitize_component(app_id or title_id)
    extension = _get_import_extension(src_path)
    folder = os.path.join(dest_root, f"{safe_title} [{safe_title_id}]", "Updates", f"v{version}")
    filename = f"{safe_title} [{safe_app_id}] [UPDATE][v{version}].{extension}"
    filename = _sanitize_component(filename)
    return folder, filename


def _get_import_extension(src_path):
    extension = get_supported_content_extension(src_path)
    if extension:
        return extension
    return os.path.splitext(os.path.basename(str(src_path or "")))[1].lstrip(".")


def _cleanup_download_path(src_path, dest_root):
    if not src_path:
        return
    src_is_dir = os.path.isdir(src_path)
    src_root = src_path if src_is_dir else os.path.dirname(src_path)
    if not src_root or not os.path.exists(src_root):
        return
    try:
        if dest_root and os.path.commonpath([os.path.abspath(src_root), os.path.abspath(dest_root)]) == os.path.abspath(dest_root):
            return
    except Exception:
        return
    try:
        if src_is_dir:
            shutil.rmtree(src_root, ignore_errors=True)
        else:
            try:
                if os.path.isdir(src_root) and not os.listdir(src_root):
                    os.rmdir(src_root)
            except Exception:
                pass
    except Exception:
        return


def _is_wrapped_import_path(path):
    return is_wrapped_content_path(path)


def _is_importable_download_file(path):
    if not path or not os.path.isfile(path):
        return False
    return is_supported_content_path(path)


def _iter_importable_download_files(src_path):
    if not src_path:
        return []
    if os.path.isfile(src_path):
        return [src_path] if _is_importable_download_file(src_path) else []
    if not os.path.isdir(src_path):
        return []
    matches = []
    for root, _, filenames in os.walk(src_path):
        for filename in filenames:
            candidate = os.path.join(root, filename)
            if _is_importable_download_file(candidate):
                matches.append(candidate)
    return matches


def _build_generic_import_destination(dest_root, src_path):
    normalized_extension = _get_import_extension(src_path)
    basename = os.path.basename(src_path)
    lowered = basename.lower()
    if normalized_extension and lowered.endswith(f".{normalized_extension}.hdf"):
        basename = basename[:-4]
    return _ensure_unique_path(os.path.join(dest_root, basename))

def _move_generic_importable_files(src_path, dest_root, excluded_paths=None, copy_files=False):
    excluded = {
        os.path.normcase(os.path.normpath(path))
        for path in (excluded_paths or [])
        if path
    }
    importable_paths = [
        path for path in _iter_importable_download_files(src_path)
        if os.path.normcase(os.path.normpath(path)) not in excluded
    ]
    if not importable_paths:
        logger.warning("No importable files found in completed download: %s", src_path)
        return None, "no importable files found"

    moved_paths = []
    try:
        for import_path in importable_paths:
            dest_path = _build_generic_import_destination(dest_root, import_path)
            if copy_files:
                shutil.copy2(import_path, dest_path)
            else:
                shutil.move(import_path, dest_path)
            dest_path = _normalize_imported_wrapped_files(dest_path)
            moved_paths.append(dest_path)
        if not copy_files:
            _cleanup_download_path(src_path, dest_root)
        logger.info("%s download to library: %s", "Copied" if copy_files else "Moved", ", ".join(moved_paths))
        return (moved_paths[0] if len(moved_paths) == 1 else moved_paths), None
    except Exception as e:
        logger.warning("Failed to move download %s: %s", src_path, e)
        return None, str(e)
def _normalize_imported_wrapped_files(dest_path):
    if not dest_path or not os.path.exists(dest_path):
        return dest_path

    if os.path.isfile(dest_path):
        candidate_paths = [dest_path]
        is_single_file = True
    elif os.path.isdir(dest_path):
        candidate_paths = []
        for root, _, filenames in os.walk(dest_path):
            for filename in filenames:
                candidate_paths.append(os.path.join(root, filename))
        is_single_file = False
    else:
        return dest_path

    renamed_single_path = dest_path
    for path in candidate_paths:
        normalized_extension = _get_import_extension(path)
        current_extension = os.path.splitext(path)[1].lstrip(".").lower()
        if not normalized_extension or normalized_extension == current_extension:
            continue
        lowered = path.lower()
        if lowered.endswith(f".{normalized_extension}.hdf"):
            normalized_path = path[:-4]
        else:
            normalized_path = f"{os.path.splitext(path)[0]}.{normalized_extension}"
        normalized_path = _ensure_unique_path(normalized_path)
        try:
            shutil.move(path, normalized_path)
            logger.info("Normalized wrapped import path: %s -> %s", path, normalized_path)
            if is_single_file and os.path.normpath(path) == os.path.normpath(dest_path):
                renamed_single_path = normalized_path
        except Exception as e:
            logger.warning("Failed to normalize wrapped import %s: %s", path, e)
    return renamed_single_path


def _move_completed_with_reason(item, update_info=None, copy_files=False):
    library_paths = get_libraries_path()
    if not library_paths:
        logger.warning("No library paths configured; cannot move download.")
        return None, "no library paths configured"
    dest_root = library_paths[0]
    src_path = item.get("path")
    if not src_path or not os.path.exists(src_path):
        logger.warning("Completed download path not found: %s", src_path)
        return None, "download path not found"

    if (
        update_info
        and update_info.get("app_type") != APP_TYPE_BASE
        and update_info.get("title_id")
        and update_info.get("version")
        and str(update_info.get("title_id")).strip().lower() != "manual"
    ):
        title_id = update_info.get("title_id")
        requested_version = update_info.get("version")
        title_name = update_info.get("title_name") or update_info.get("expected_name")
        update_path, actual_version = _select_completed_update_candidate(src_path)
        if not update_path or not actual_version:
            if copy_files:
                moved_result, move_reason = _move_generic_importable_files(src_path, dest_root, copy_files=True)
            else:
                moved_result, move_reason = _move_generic_importable_files(src_path, dest_root)
            if moved_result:
                logger.info(
                    "Imported completed download for %s without update payload; kept generic files from %s.",
                    title_id,
                    src_path,
                )
                return moved_result, None
            logger.warning("No update file found for %s v%s in %s", title_id, requested_version, src_path)
            return None, "no update file found"
        highest_owned = _get_highest_owned_update_version(title_id)
        effective_highest_owned = max(highest_owned, _get_local_known_update_version(title_id))
        if actual_version <= effective_highest_owned:
            if copy_files:
                moved_result, move_reason = _move_generic_importable_files(
                    src_path, dest_root, excluded_paths=[update_path], copy_files=True,
                )
            else:
                moved_result, move_reason = _move_generic_importable_files(
                    src_path, dest_root, excluded_paths=[update_path],
                )
            if moved_result:
                logger.info(
                    "Skipped stale update %s v%s and imported remaining files from %s.",
                    title_id,
                    actual_version,
                    src_path,
                )
                return moved_result, None
            return None, f"duplicate update: downloaded v{actual_version} is not newer than known v{effective_highest_owned}"
        if requested_version and int(actual_version) != int(requested_version):
            logger.info(
                "Importing completed update %s v%s although AeroFoil requested v%s because it upgrades owned v%s.",
                title_id,
                actual_version,
                requested_version,
                highest_owned,
            )
        dest_dir, dest_filename = _build_update_destination(
            dest_root,
            title_id,
            update_info.get("app_id"),
            title_name,
            actual_version,
            update_path,
        )
        dest_path = os.path.join(dest_dir, dest_filename)
        dest_path = _ensure_unique_path(dest_path)
        try:
            os.makedirs(dest_dir, exist_ok=True)
            if copy_files:
                shutil.copy2(update_path, dest_path)
            else:
                shutil.move(update_path, dest_path)
            logger.info("%s update to library: %s", "Copied" if copy_files else "Moved", dest_path)
            _record_local_content_index(title_id=title_id, app_id=update_info.get("app_id"), app_type=APP_TYPE_UPD, version=actual_version)
            if not copy_files:
                _cleanup_download_path(src_path, dest_root)
            return dest_path, None
        except Exception as e:
            logger.warning("Failed to move update %s: %s", update_path, e)
            return None, str(e)

    if os.path.abspath(os.path.dirname(src_path)) == os.path.abspath(dest_root):
        duplicate_reason = _detect_duplicate_reason_for_path(src_path)
        if duplicate_reason:
            return None, duplicate_reason
        moved_path = _normalize_imported_wrapped_files(src_path)
        _record_imported_file_content(moved_path)
        return moved_path, None
    duplicate_reason = _detect_duplicate_reason_for_path(src_path)
    if duplicate_reason:
        return None, duplicate_reason
    if copy_files:
        moved_result, move_reason = _move_generic_importable_files(src_path, dest_root, copy_files=True)
    else:
        moved_result, move_reason = _move_generic_importable_files(src_path, dest_root)
    if moved_result:
        for moved_path in _coerce_moved_paths(moved_result):
            _record_imported_file_content(moved_path)
    return moved_result, move_reason


def _move_completed(item, update_info=None, copy_files=False):
    if copy_files:
        moved_result, _ = _move_completed_with_reason(item, update_info=update_info, copy_files=True)
    else:
        moved_result, _ = _move_completed_with_reason(item, update_info=update_info)
    return moved_result


def _is_duplicate_reason(reason):
    text = str(reason or "").strip().lower()
    return text.startswith("duplicate")


def _track_duplicate_locked(info, item, reason, key=None):
    duplicates = _state.get("duplicates")
    if not isinstance(duplicates, list):
        duplicates = []
        _state["duplicates"] = duplicates
    label = str((item or {}).get("name") or (info or {}).get("expected_name") or _format_pending_label(info)).strip()
    duplicates.append({
        "id": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "label": label,
        "reason": str(reason or "duplicate"),
        "protocol": str((info or {}).get("protocol") or (item or {}).get("protocol") or "").strip().lower() or None,
        "client_type": str((info or {}).get("client_type") or (item or {}).get("client_type") or "").strip().lower() or None,
        "path": str((item or {}).get("path") or "").strip() or None,
        "key": str(key or ""),
    })
    if len(duplicates) > 200:
        del duplicates[:-200]
    _persist_downloads_state_locked()


def _open_content_index_db():
    os.makedirs(os.path.dirname(_DOWNLOADS_CONTENT_INDEX_FILE), exist_ok=True)
    conn = sqlite3.connect(_DOWNLOADS_CONTENT_INDEX_FILE)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS local_content ("
        "title_id TEXT NOT NULL,"
        "app_id TEXT,"
        "app_type TEXT NOT NULL,"
        "version INTEGER NOT NULL DEFAULT 0,"
        "updated_at INTEGER NOT NULL,"
        "PRIMARY KEY (title_id, app_type, version)"
        ")"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_local_content_title_type ON local_content(title_id, app_type)")
    return conn


def _record_local_content_index(title_id=None, app_id=None, app_type=None, version=None):
    title_id = str(title_id or "").strip().upper()
    app_type = str(app_type or "").strip().upper()
    if not title_id or not app_type:
        return
    try:
        version_int = int(version or 0)
    except Exception:
        version_int = 0
    now = int(time.time())
    try:
        conn = _open_content_index_db()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO local_content (title_id, app_id, app_type, version, updated_at) VALUES (?, ?, ?, ?, ?)",
                (title_id, (str(app_id or "").strip().upper() or None), app_type, version_int, now),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("Failed to update local content index: %s", exc)


def _get_local_known_update_version(title_id):
    title_id = str(title_id or "").strip().upper()
    if not title_id:
        return 0
    try:
        conn = _open_content_index_db()
        try:
            row = conn.execute(
                "SELECT MAX(version) FROM local_content WHERE title_id = ? AND app_type = ?",
                (title_id, APP_TYPE_UPD),
            ).fetchone()
            value = int((row or [0])[0] or 0)
            return max(value, 0)
        finally:
            conn.close()
    except Exception:
        return 0


def _derive_title_defaults_for_snake_pass(title_id, app_type, version):
    if str(title_id or "").strip().upper() == _SNAKE_PASS_BASE_TITLE_ID and str(app_type or "").strip().upper() == APP_TYPE_BASE:
        try:
            version_int = int(version or 0)
        except Exception:
            version_int = 0
        if version_int <= 0:
            return _SNAKE_PASS_BASE_MIN_VERSION
    return version


def _detect_duplicate_reason_for_path(src_path):
    for importable in _iter_importable_download_files(src_path):
        try:
            _, success, contents, _ = titles_lib.identify_file(importable)
        except BaseException:
            success = False
            contents = []
        if not success or not contents:
            continue
        for content in contents:
            title_id = str(content.get("title_id") or "").strip().upper()
            app_id = str(content.get("app_id") or "").strip().upper()
            app_type = str(content.get("type") or "").strip().upper()
            raw_version = content.get("version")
            try:
                version = int(raw_version) if raw_version is not None else 0
            except Exception:
                version = 0
            version = _derive_title_defaults_for_snake_pass(title_id, app_type, version)
            if not title_id:
                continue
            title_apps = get_all_title_apps(title_id) or []
            if app_type == APP_TYPE_BASE:
                if any(str(app.get("app_type") or "").upper() == APP_TYPE_BASE and app.get("owned") for app in title_apps):
                    return f"duplicate basegame: {title_id} already exists in library"
            elif app_type == APP_TYPE_UPD:
                owned_versions = []
                for app in title_apps:
                    if str(app.get("app_type") or "").upper() != APP_TYPE_UPD:
                        continue
                    if not app.get("owned"):
                        continue
                    try:
                        owned_versions.append(int(app.get("app_version") or 0))
                    except Exception:
                        continue
                known_highest = max(owned_versions) if owned_versions else 0
                local_highest = _get_local_known_update_version(title_id)
                known_highest = max(known_highest, local_highest)
                if version <= known_highest:
                    return f"duplicate update: {title_id} v{version} already known (latest v{known_highest})"
    return None


def _record_imported_file_content(import_path):
    if not import_path or not os.path.exists(import_path):
        return
    try:
        _, success, contents, _ = titles_lib.identify_file(import_path)
    except BaseException:
        success = False
        contents = []
    if not success:
        return
    for content in contents or []:
        title_id = str(content.get("title_id") or "").strip().upper()
        app_id = str(content.get("app_id") or "").strip().upper()
        app_type = str(content.get("type") or "").strip().upper()
        raw_version = content.get("version")
        try:
            version = int(raw_version) if raw_version is not None else 0
        except Exception:
            version = 0
        version = _derive_title_defaults_for_snake_pass(title_id, app_type, version)
        _record_local_content_index(title_id=title_id, app_id=app_id, app_type=app_type, version=version)
