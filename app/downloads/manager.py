import logging
import os
import re
import shutil
import threading
import time
import unicodedata

from app import titles as titles_lib
from app.constants import ALLOWED_EXTENSIONS, APP_TYPE_UPD
from app.db import get_all_title_apps, get_all_titles, get_libraries_path
from app.downloads.client import (
    TORRENT_CLIENT_TYPES,
    USENET_CLIENT_TYPES,
    list_active_downloads,
    list_completed_downloads,
    queue_download,
    remove_completed_download,
)
from app.downloads.prowlarr import ProwlarrClient, pick_best_result
from app.library import _ensure_unique_path, _sanitize_component, enqueue_cleanup_roots, enqueue_organize_paths
from app.settings import load_settings

logger = logging.getLogger("downloads.manager")

_state_lock = threading.Lock()
_state = {
    "running": False,
    "last_run": 0.0,
    "pending": {},  # key -> info
    "completed": set(),
}


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
    client_type = str(client_cfg.get("type") or "").strip().lower()
    if protocol == "torrent":
        return bool(client_cfg.get("url") and client_type in TORRENT_CLIENT_TYPES)
    if protocol == "usenet":
        return bool(client_cfg.get("url") and client_cfg.get("api_key") and client_type in USENET_CLIENT_TYPES)
    return False


def _get_configured_protocols(downloads):
    return [
        protocol for protocol in ("torrent", "usenet")
        if _is_protocol_client_configured(downloads, protocol)
    ]


def _get_completed_poll_targets(downloads):
    targets = []
    for protocol in ("torrent", "usenet"):
        if _is_protocol_client_configured(downloads, protocol):
            targets.append((protocol, _get_protocol_client_cfg(downloads, protocol)))
    return targets


def get_downloads_state():
    with _state_lock:
        pending_items = []
        for key, info in _state["pending"].items():
            expected_name = str(info.get("expected_name") or "").strip()
            pending_items.append({
                "key": key,
                "title_id": info.get("title_id"),
                "version": info.get("version"),
                "expected_name": expected_name or None,
                "hash": info.get("hash"),
                "id": info.get("id"),
                "protocol": info.get("protocol"),
                "client_type": info.get("client_type"),
                "label": _format_pending_label(info),
            })
        return {
            "running": _state["running"],
            "last_run": _state["last_run"],
            "pending": pending_items,
            "completed": sorted(_state["completed"]),
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


def run_downloads_job(scan_cb=None, post_cb=None):
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
        return False, "No download client is configured.", []
    try:
        items = []
        for protocol, client_cfg in targets:
            items.extend(list_active_downloads(protocol, client_cfg))
        items.sort(key=lambda item: ((item.get("protocol") or ""), (item.get("name") or "").lower()))
        return True, None, items
    except Exception as e:
        return False, str(e), []


def _process_downloads(downloads, scan_cb=None, post_cb=None):
    prowlarr_cfg = downloads.get("prowlarr", {})
    if not prowlarr_cfg.get("url") or not prowlarr_cfg.get("api_key"):
        logger.warning("Downloads enabled, but Prowlarr is not configured.")
        return
    allowed_protocols = _get_configured_protocols(downloads)
    if not allowed_protocols:
        logger.warning("Downloads enabled, but no download client is configured.")
        return

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
            blacklist_terms=blacklist_terms,
            min_seeders=min_seeders,
            min_age_minutes=min_age_minutes,
            search_limit=search_limit,
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
        blacklist_terms=downloads.get("blacklist_terms") or [],
        min_seeders=_get_torrent_min_seeders(downloads),
        min_age_minutes=_get_usenet_min_age_minutes(downloads),
        search_limit=search_limit,
        allow_duplicates=False,
        allowed_protocols=allowed_protocols,
    )
    return ok, message


def search_update_options(title_id, version, limit=20):
    settings = load_settings()
    downloads = settings.get("downloads", {})
    prowlarr_cfg = downloads.get("prowlarr", {})
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
                blacklist_terms=downloads.get("blacklist_terms") or [],
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
        }
        for r in (results or [])[:limit]
    ]
    return True, None, trimmed


def queue_download_url(download_url, expected_name=None, update_only=False, expected_version=None, title_id=None, protocol=None):
    settings = load_settings()
    downloads = settings.get("downloads", {})
    resolved_protocol = _infer_protocol(download_url=download_url, explicit_protocol=protocol)
    if not resolved_protocol:
        return False, "Unable to determine download protocol."
    client_cfg = _get_protocol_client_cfg(downloads, resolved_protocol)
    if not _is_protocol_client_configured(downloads, resolved_protocol):
        return False, f"No {resolved_protocol} client is configured."
    queue_update_only = bool(update_only and resolved_protocol != "usenet")
    ok, message, item_id = queue_download(
        resolved_protocol,
        client_cfg,
        download_url,
        expected_name=expected_name,
        update_only=queue_update_only,
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
    allow_duplicates=True,
    allowed_protocols=None,
):
    key = f"{update['title_id']}:{update['version']}"
    if not allow_duplicates and _already_tracked(key):
        return False, "Update is already queued."

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
            blacklist_terms=blacklist_terms,
            allowed_protocols=allowed_protocols,
            require_exact_version=True,
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


def _already_tracked(key):
    with _state_lock:
        return key in _state["pending"] or key in _state["completed"]


def _track_pending(key, update, item_id, expected_name=None, protocol=None, client_type=None):
    with _state_lock:
        _state["pending"][key] = {
            "title_id": update["title_id"],
            "version": update["version"],
            "hash": item_id,
            "id": item_id,
            "expected_name": expected_name or update.get("title_name"),
            "title_name": update.get("title_name"),
            "protocol": protocol,
            "client_type": client_type,
        }


def _match_completed_item(info, completed_items):
    item_id = info.get("id") or info.get("hash")
    if item_id:
        match = next((item for item in completed_items if (item.get("id") or item.get("hash")) == item_id), None)
        if match:
            return match
    expected = (info.get("expected_name") or "").lower()
    if expected:
        return next((item for item in completed_items if expected in (item.get("name") or "").lower()), None)
    return None


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


def _select_completed_update_candidate(src_path):
    candidates = []
    for path in _iter_completed_files(src_path) or []:
        filename = os.path.basename(path)
        version = _extract_update_version_from_name(filename)
        if version is None:
            continue
        lowered = filename.lower()
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        rank = 0 if lowered.endswith(".nfo") else 1
        candidates.append((rank, size, path, version))
    if not candidates:
        return None, None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    _, _, path, version = candidates[0]
    return path, version


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


def _check_completed(downloads, scan_cb=None, post_cb=None):
    poll_targets = _get_completed_poll_targets(downloads)
    if not poll_targets:
        return

    completed_by_protocol = {}
    for protocol, client_cfg in poll_targets:
        items = list_completed_downloads(protocol, client_cfg)
        completed_by_protocol[protocol] = {
            "client_cfg": client_cfg,
            "items": items,
            "matched_ids": set(),
        }
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
            match = _match_completed_item(info, bucket["items"])
            if not match:
                continue
            moved_match_paths = _coerce_moved_paths(_move_completed(match, info))
            if not moved_match_paths:
                logger.warning(
                    "Matched completed download for pending key %s, but move failed. Keeping pending entry for retry.",
                    key,
                )
                continue
            matched_id = match.get("id") or match.get("hash")
            if matched_id:
                bucket["matched_ids"].add(matched_id)
            _state["pending"].pop(key, None)
            _state["completed"].add(key)
            moved_paths.extend(moved_match_paths)
            if matched_id:
                ok, message = remove_completed_download(protocol, bucket["client_cfg"], matched_id)
                if not ok:
                    logger.warning("Failed to remove completed %s item %s: %s", protocol, matched_id, message)
            newly_completed = True

        for protocol, bucket in completed_by_protocol.items():
            unmatched_count = 0
            for item in bucket["items"]:
                item_id = item.get("id") or item.get("hash")
                if item_id and item_id in bucket["matched_ids"]:
                    continue
                moved_item_paths = _coerce_moved_paths(_adopt_untracked_completed_item(item))
                if moved_item_paths:
                    matched_id = item.get("id") or item.get("hash")
                    if matched_id:
                        ok, message = remove_completed_download(protocol, bucket["client_cfg"], matched_id)
                        if not ok:
                            logger.warning("Failed to remove adopted %s item %s: %s", protocol, matched_id, message)
                    moved_paths.extend(moved_item_paths)
                    newly_completed = True
                    continue
                unmatched_count += 1
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
    if not name:
        return None
    match = re.search(r"\[v(\d+)\]", name, re.IGNORECASE)
    if not match:
        match = re.search(r"(?<![a-z0-9])v(\d+)(?!\.\d)", name, re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return None


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


def _build_update_destination(dest_root, title_id, title_name, version, src_path):
    safe_title = _sanitize_component(title_name or title_id)
    safe_title_id = _sanitize_component(title_id)
    extension = _get_import_extension(src_path)
    folder = os.path.join(dest_root, f"{safe_title} [{safe_title_id}]", "Updates", f"v{version}")
    filename = f"{safe_title} [{safe_title_id}] [UPDATE][v{version}].{extension}"
    filename = _sanitize_component(filename)
    return folder, filename


def _get_import_extension(src_path):
    name = os.path.basename(str(src_path or ""))
    lowered = name.lower()
    if lowered.endswith(".nsp.hdf"):
        # Some wrapped usenet releases keep the real content extension before .hdf.
        return "nsp"
    if lowered.endswith(".nsz.hdf"):
        return "nsz"
    return os.path.splitext(name)[1].lstrip(".")


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
    lowered = str(path or "").lower()
    return any(lowered.endswith(f".{ext}.hdf") for ext in ALLOWED_EXTENSIONS)


def _is_importable_download_file(path):
    if not path or not os.path.isfile(path):
        return False
    extension = os.path.splitext(path)[1].lstrip(".").lower()
    return extension in ALLOWED_EXTENSIONS or _is_wrapped_import_path(path)


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


def _move_completed(item, update_info=None):
    library_paths = get_libraries_path()
    if not library_paths:
        logger.warning("No library paths configured; cannot move download.")
        return
    dest_root = library_paths[0]
    src_path = item.get("path")
    if not src_path or not os.path.exists(src_path):
        logger.warning("Completed download path not found: %s", src_path)
        return

    if (
        update_info
        and update_info.get("title_id")
        and update_info.get("version")
        and str(update_info.get("title_id")).strip().lower() != "manual"
    ):
        title_id = update_info.get("title_id")
        version = update_info.get("version")
        title_name = update_info.get("title_name") or update_info.get("expected_name")
        update_path = _select_update_file_path(src_path, version)
        if not update_path:
            logger.warning("No update file found for %s v%s in %s", title_id, version, src_path)
            return
        dest_dir, dest_filename = _build_update_destination(dest_root, title_id, title_name, version, update_path)
        dest_path = os.path.join(dest_dir, dest_filename)
        dest_path = _ensure_unique_path(dest_path)
        try:
            os.makedirs(dest_dir, exist_ok=True)
            shutil.move(update_path, dest_path)
            logger.info("Moved update to library: %s", dest_path)
            _cleanup_download_path(src_path, dest_root)
            return dest_path
        except Exception as e:
            logger.warning("Failed to move update %s: %s", update_path, e)
            return None

    if os.path.abspath(os.path.dirname(src_path)) == os.path.abspath(dest_root):
        return _normalize_imported_wrapped_files(src_path)
    importable_paths = _iter_importable_download_files(src_path)
    if not importable_paths:
        logger.warning("No importable files found in completed download: %s", src_path)
        return None
    moved_paths = []
    try:
        for import_path in importable_paths:
            dest_path = _build_generic_import_destination(dest_root, import_path)
            shutil.move(import_path, dest_path)
            dest_path = _normalize_imported_wrapped_files(dest_path)
            moved_paths.append(dest_path)
        _cleanup_download_path(src_path, dest_root)
        logger.info("Moved download to library: %s", ", ".join(moved_paths))
        return moved_paths[0] if len(moved_paths) == 1 else moved_paths
    except Exception as e:
        logger.warning("Failed to move download %s: %s", src_path, e)
        return None
