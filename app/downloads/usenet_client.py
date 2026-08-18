import os
import logging
import time
import hashlib
import base64

import requests

from app.downloads.constants import DOWNLOADS_USER_AGENT
from app.downloads.update_selection import (
    NZB_DLC_SELECTION_ERROR,
    NZB_UPDATE_SELECTION_ERROR,
    get_matching_dlc_indices,
    get_matching_update_indices,
    poll_update_file_names,
)

logger = logging.getLogger("downloads.sabnzbd")

NZBGET_GROUP_STATUS_DOWNLOADING = ("DOWNLOADING", "PAUSED", "QUEUED", "LOADING")
NZBGET_GROUP_STATUS_COMPLETED = ("SUCCESS", "WARNING")
NZBGET_GROUP_STATUS_FAILED = ("FAILURE", "DELETED")

def test_sabnzbd(url, api_key, timeout_seconds=10):
    if not url:
        return False, "Client URL is required."
    if not api_key:
        return False, "SABnzbd API key is required."
    try:
        payload = _sab_request(
            url,
            api_key,
            mode="version",
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        return False, str(exc)
    version = payload.get("version") or payload.get("sabnzbd_version")
    return True, f"SABnzbd OK{f' (v{version})' if version else ''}."


def add_nzb(
    url,
    api_key,
    download_url,
    category=None,
    timeout_seconds=15,
    expected_name=None,
    update_only=False,
    dlc_only=False,
    exclude_russian=False,
    expected_update_number=None,
    expected_version=None,
):
    if not download_url:
        return False, "Download URL is required.", None
    if not api_key:
        return False, "SABnzbd API key is required.", None
    try:
        priority = -2 if update_only or dlc_only else None
        payload = _sab_request(
            url,
            api_key,
            mode="addurl",
            timeout_seconds=timeout_seconds,
            name=download_url,
            cat=category or "",
            priority=priority,
        )
    except Exception as exc:
        return False, str(exc), None
    status = payload.get("status")
    if status in (True, "true", "True", 1, "1"):
        nzo_id = payload.get("nzo_ids")
        if isinstance(nzo_id, list) and nzo_id:
            nzo_id = nzo_id[0]
        elif isinstance(nzo_id, str) and "," in nzo_id:
            nzo_id = nzo_id.split(",", 1)[0].strip()
        nzo_id = str(nzo_id or "").strip() or None
        if (update_only or dlc_only) and nzo_id:
            if update_only:
                ok, message = _restrict_job_to_matching_update_files(
                    url,
                    api_key,
                    nzo_id,
                    timeout_seconds=timeout_seconds,
                    exclude_russian=exclude_russian,
                    expected_update_number=expected_update_number,
                    expected_version=expected_version,
                )
                no_match_error = NZB_UPDATE_SELECTION_ERROR
            else:
                ok, message = _restrict_job_to_matching_dlc_files(
                    url,
                    api_key,
                    nzo_id,
                    timeout_seconds=timeout_seconds,
                    exclude_russian=exclude_russian,
                )
                no_match_error = NZB_DLC_SELECTION_ERROR
            if not ok:
                _delete_job(url, api_key, nzo_id, timeout_seconds=timeout_seconds)
                return False, message or no_match_error, None
            if not _resume_job(url, api_key, nzo_id, timeout_seconds=timeout_seconds):
                _delete_job(url, api_key, nzo_id, timeout_seconds=timeout_seconds)
                return False, "SABnzbd accepted NZB but failed to resume the paused job.", None
        return True, "SABnzbd accepted NZB.", nzo_id
    message = payload.get("error") or payload.get("message") or "SABnzbd rejected NZB."
    return False, str(message), None


def list_active(url, api_key, category=None, timeout_seconds=15):
    if not url or not api_key:
        return []
    try:
        payload = _sab_request(
            url,
            api_key,
            mode="queue",
            timeout_seconds=timeout_seconds,
        )
    except Exception:
        return []
    queue = payload.get("queue") if isinstance(payload, dict) else {}
    raw_slots = queue.get("slots") or []
    queue_speed = _bytes_per_second(queue.get("kbpersec"))
    slots = []
    for item in raw_slots:
        if not isinstance(item, dict):
            continue
        item_category = str(item.get("cat") or item.get("category") or "").strip()
        if category and item_category != category:
            continue
        slots.append(item)
    active = []
    for item in slots:
        nzo_id = str(item.get("nzo_id") or "").strip() or None
        percentage = _to_float(item.get("percentage"), None)
        if percentage is None:
            percentage = _to_float(item.get("mb"), 0.0)
            mb_left = _to_float(item.get("mbleft"), 0.0)
            if percentage > 0:
                percentage = max(0.0, min(((percentage - mb_left) / percentage) * 100.0, 100.0))
            else:
                percentage = 0.0
        eta_seconds = _parse_eta_seconds(item.get("timeleft"))
        size_bytes = _mb_to_bytes(item.get("mb"))
        left_bytes = _mb_to_bytes(item.get("mbleft"))
        active.append({
            "id": nzo_id,
            "hash": nzo_id,
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "name": item.get("filename") or item.get("nzb_name") or item.get("name") or "",
            "status": item.get("status") or queue.get("status") or "",
            "progress": max(0.0, min(_to_float(percentage, 0.0), 100.0)),
            "down_speed": None,
            "up_speed": 0,
            "peers": 0,
            "seeders": 0,
            "leechers": 0,
            "eta": eta_seconds,
            "size": size_bytes,
            "downloaded": max(size_bytes - left_bytes, 0),
            "path": item.get("storage") or item.get("path") or "",
            "queue_down_speed": queue_speed,
        })
    return active


def list_history(url, api_key, category=None, timeout_seconds=15):
    if not url or not api_key:
        return []
    try:
        payload = _sab_request(
            url,
            api_key,
            mode="history",
            timeout_seconds=timeout_seconds,
        )
    except Exception:
        return []
    history = payload.get("history") if isinstance(payload, dict) else {}
    slots = history.get("slots") or []
    completed_dir = _normalize_completed_root(
        history.get("completed_dir")
        or payload.get("completed_dir")
    )
    history_items = []
    for item in slots:
        if not isinstance(item, dict):
            continue
        item_category = str(item.get("category") or item.get("cat") or "").strip()
        if category and item_category != category:
            continue
        status_text = str(item.get("status") or "").strip()
        status = status_text.lower()
        completed_flag = str(item.get("completed") or "").lower()
        terminal_state = _classify_history_terminal_state(status, completed_flag)
        if not terminal_state:
            continue
        nzo_id = str(item.get("nzo_id") or "").strip() or None
        path = item.get("storage") or item.get("path") or item.get("downloaded_path") or ""
        path = str(path or "").strip()
        normalized_path = _normalize_completed_root(path)
        if terminal_state == "completed":
            if not normalized_path:
                # Avoid treating the global completed_dir as a per-job path.
                continue
        item_completed_dir = _normalize_completed_root(item.get("completed_dir"))
        if terminal_state == "completed" and normalized_path == (item_completed_dir or completed_dir):
            # Avoid treating SABnzbd's shared completed_dir as a per-job path.
            continue
        history_items.append({
            "id": nzo_id,
            "hash": nzo_id,
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "status": status_text,
            "state": terminal_state,
            "state_reason": _extract_history_state_reason(item, terminal_state),
            "path": path,
            "name": item.get("name") or item.get("nzb_name") or item.get("filename") or "",
        })
    return history_items


def list_completed(url, api_key, category=None, timeout_seconds=15):
    return [
        item for item in list_history(
            url,
            api_key,
            category=category,
            timeout_seconds=timeout_seconds,
        )
        if item.get("state") == "completed"
    ]


def remove_history(url, api_key, item_id, timeout_seconds=15, delete_files=False):
    if not item_id:
        return False, "SABnzbd item id is required."
    if not api_key:
        return False, "SABnzbd API key is required."
    try:
        payload = _sab_request(
            url,
            api_key,
            mode="history",
            timeout_seconds=timeout_seconds,
            name="delete",
            value=item_id,
            del_files=1 if delete_files else 0,
            output="json",
        )
    except Exception as exc:
        return False, str(exc)
    status = payload.get("status")
    if status in (True, "true", "True", 1, "1"):
        return True, "SABnzbd history entry removed."
    message = payload.get("error") or payload.get("message") or "SABnzbd failed to remove history entry."
    return False, str(message)


def remove_queue_item(url, api_key, item_id, timeout_seconds=15, delete_files=False):
    if not item_id:
        return False, "SABnzbd item id is required."
    if not api_key:
        return False, "SABnzbd API key is required."
    try:
        payload = _sab_request(
            url,
            api_key,
            mode="queue",
            timeout_seconds=timeout_seconds,
            name="delete",
            value=item_id,
            del_files=1 if delete_files else 0,
            output="json",
        )
    except Exception as exc:
        return False, str(exc)
    status = payload.get("status")
    if status in (True, "true", "True", 1, "1"):
        return True, "SABnzbd queue item removed."
    message = payload.get("error") or payload.get("message") or "SABnzbd failed to remove queue item."
    return False, str(message)


def _normalize_completed_root(path):
    text = str(path or "").strip()
    if not text:
        return ""
    normalized = os.path.normpath(text)
    return os.path.normcase(normalized)


def _classify_history_terminal_state(status, completed_flag):
    if status in ("completed", "complete") or completed_flag in ("1", "true", "yes"):
        return "completed"
    if any(token in status for token in ("cancel", "abort", "delete", "deleted")):
        return "cancelled"
    if any(token in status for token in ("fail", "error")):
        return "failed"
    return None


def _extract_history_state_reason(item, terminal_state):
    if terminal_state == "completed":
        return None
    for field in ("fail_message", "stage_log", "action_line"):
        value = str((item or {}).get(field) or "").strip()
        if value:
            return value
    status_text = str((item or {}).get("status") or "").strip()
    return status_text or None


def _sab_request(base_url, api_key, mode, timeout_seconds=15, **params):
    base = str(base_url or "").rstrip("/")
    if not base:
        raise ValueError("Client URL is required.")
    query = {
        "apikey": api_key,
        "mode": mode,
        "output": "json",
    }
    query.update(params)
    response = requests.get(
        f"{base}/api",
        params=query,
        headers={"User-Agent": DOWNLOADS_USER_AGENT},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, dict) and payload.get("status") is False and payload.get("error"):
        raise RuntimeError(str(payload.get("error")))
    return payload if isinstance(payload, dict) else {}


def _get_job_files(url, api_key, nzo_id, timeout_seconds=15):
    payload = _sab_request(
        url,
        api_key,
        mode="get_files",
        timeout_seconds=timeout_seconds,
        value=nzo_id,
    )
    files = payload.get("files") if isinstance(payload, dict) else None
    return files if isinstance(files, list) else []


def _delete_job_files(url, api_key, nzo_id, nzf_ids, timeout_seconds=15):
    if not nzf_ids:
        return True
    payload = _sab_request(
        url,
        api_key,
        mode="queue",
        timeout_seconds=timeout_seconds,
        name="delete_nzf",
        value=nzo_id,
        value2=",".join(str(item) for item in nzf_ids if str(item or "").strip()),
    )
    status = payload.get("status")
    return status in (True, "true", "True", 1, "1")


def _resume_job(url, api_key, nzo_id, timeout_seconds=15):
    payload = _sab_request(
        url,
        api_key,
        mode="queue",
        timeout_seconds=timeout_seconds,
        name="resume",
        value=nzo_id,
    )
    return payload.get("status") in (True, "true", "True", 1, "1")


def _delete_job(url, api_key, nzo_id, timeout_seconds=15, delete_files=False):
    try:
        _sab_request(
            url,
            api_key,
            mode="queue",
            timeout_seconds=timeout_seconds,
            name="delete",
            value=nzo_id,
            del_files=1 if delete_files else 0,
        )
    except Exception:
        return False
    return True


def _restrict_job_to_matching_update_files(
    url,
    api_key,
    nzo_id,
    timeout_seconds=15,
    exclude_russian=False,
    expected_update_number=None,
    expected_version=None,
):
    files = poll_update_file_names(
        lambda: _get_job_files(url, api_key, nzo_id, timeout_seconds=timeout_seconds),
        sleep_fn=time.sleep,
    )
    if not files:
        return False, "Unable to resolve SABnzbd file list for update selection."

    file_names = [str(item.get("filename") or "") for item in files]
    keep_indices = get_matching_update_indices(
        file_names,
        expected_update_number=expected_update_number,
        expected_version=expected_version,
        exclude_russian=exclude_russian,
    )
    if not keep_indices:
        return False, NZB_UPDATE_SELECTION_ERROR

    keep_set = set(keep_indices)
    remove_ids = []
    for idx, file_info in enumerate(files):
        if idx in keep_set:
            continue
        nzf_id = str(file_info.get("nzf_id") or "").strip()
        if nzf_id:
            remove_ids.append(nzf_id)
    if remove_ids and not _delete_job_files(url, api_key, nzo_id, remove_ids, timeout_seconds=timeout_seconds):
        return False, "Failed to restrict SABnzbd job to matching update files."
    return True, None


def _restrict_job_to_matching_dlc_files(
    url,
    api_key,
    nzo_id,
    timeout_seconds=15,
    exclude_russian=False,
):
    files = poll_update_file_names(
        lambda: _get_job_files(url, api_key, nzo_id, timeout_seconds=timeout_seconds),
        sleep_fn=time.sleep,
    )
    if not files:
        return False, "Unable to resolve SABnzbd file list for DLC selection."

    file_names = [str(item.get("filename") or "") for item in files]
    keep_indices = get_matching_dlc_indices(
        file_names,
        exclude_russian=exclude_russian,
    )
    if not keep_indices:
        return False, NZB_DLC_SELECTION_ERROR

    keep_set = set(keep_indices)
    remove_ids = []
    for idx, file_info in enumerate(files):
        if idx in keep_set:
            continue
        nzf_id = str(file_info.get("nzf_id") or "").strip()
        if nzf_id:
            remove_ids.append(nzf_id)
    if remove_ids and not _delete_job_files(url, api_key, nzo_id, remove_ids, timeout_seconds=timeout_seconds):
        return False, "Failed to restrict SABnzbd job to matching DLC files."
    return True, None


def _to_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _mb_to_bytes(value):
    try:
        return int(float(value) * 1024 * 1024)
    except Exception:
        return 0


def _bytes_per_second(value):
    try:
        return int(float(value) * 1024)
    except Exception:
        return 0




def _parse_eta_seconds(value):
    raw = str(value or "").strip()
    if not raw:
        return -1
    if raw.isdigit():
        return int(raw)
    parts = raw.split(":")
    if len(parts) == 3 and all(part.isdigit() for part in parts):
        hours, minutes, seconds = [int(part) for part in parts]
        return (hours * 3600) + (minutes * 60) + seconds
    if len(parts) == 2 and all(part.isdigit() for part in parts):
        minutes, seconds = [int(part) for part in parts]
        return (minutes * 60) + seconds
    return -1


def test_nzbget(url, username=None, password=None, timeout_seconds=10):
    if not url:
        return False, "Client URL is required."
    try:
        version = _nzbget_request(url, username, password, "version", timeout_seconds=timeout_seconds)
    except Exception as exc:
        return False, str(exc)
    version_text = str(version or "").strip()
    return True, f"NZBGet OK{f' (v{version_text})' if version_text else ''}."


def add_nzbget(
    url,
    username,
    password,
    download_url,
    category=None,
    timeout_seconds=15,
    expected_name=None,
    update_only=False,
    dlc_only=False,
    exclude_russian=False,
    expected_update_number=None,
    expected_version=None,
):
    if not download_url:
        return False, "Download URL is required.", None
    if not username:
        return False, "NZBGet username is required.", None
    if password is None:
        return False, "NZBGet password is required.", None
    name = str(expected_name or "").strip() or os.path.basename(str(download_url or "").split("?", 1)[0]) or "aerofoil.nzb"
    try:
        # append(name, url, category, priority, addPaused, dupeKey, dupeScore, dupeMode)
        result = _nzbget_request(
            url,
            username,
            password,
            "append",
            params=[name, str(download_url), str(category or ""), 0, true, bool(update_only), "", 0, "SCORE"],
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        return False, str(exc), None
    if not result:
        return False, "NZBGet rejected NZB.", None
    group = _nzbget_find_group_by_name(url, username, password, name, category=category, timeout_seconds=timeout_seconds)
    nzo_id = str((group or {}).get("NZBID") or "").strip() or None
    return True, "NZBGet accepted NZB.", nzo_id


def list_active_nzbget(url, username, password, category=None, timeout_seconds=15):
    if not url or not username or password is None:
        return []
    try:
        groups = _nzbget_request(url, username, password, "listgroups", timeout_seconds=timeout_seconds)
    except Exception:
        return []
    out = []
    for item in (groups or []):
        if not isinstance(item, dict):
            continue
        cat = str(item.get("Category") or "").strip()
        if category and cat != category:
            continue
        status = str(item.get("Status") or "").strip().upper()
        if status not in NZBGET_GROUP_STATUS_DOWNLOADING:
            continue
        total_size = _to_int(item.get("FileSizeMB"), 0) * 1024 * 1024
        remaining_mb = _to_int(item.get("RemainingSizeMB"), 0)
        remaining = max(remaining_mb, 0) * 1024 * 1024
        downloaded = max(total_size - remaining, 0)
        progress = 0.0 if total_size <= 0 else max(0.0, min((float(downloaded) / float(total_size)) * 100.0, 100.0))
        out.append({
            "id": str(item.get("NZBID") or "").strip() or None,
            "hash": str(item.get("NZBID") or "").strip() or None,
            "protocol": "usenet",
            "client_type": "nzbget",
            "name": str(item.get("NZBName") or item.get("Name") or "").strip(),
            "status": status.lower(),
            "progress": progress,
            "down_speed": max(_to_int(item.get("DownloadRate"), 0), 0),
            "up_speed": 0,
            "peers": 0,
            "seeders": 0,
            "leechers": 0,
            "eta": _to_int(item.get("EstimatedSeconds"), -1),
            "size": total_size,
            "downloaded": downloaded,
            "path": str(item.get("DestDir") or "").strip(),
        })
    return out


def list_history_nzbget(url, username, password, category=None, timeout_seconds=15):
    if not url or not username or password is None:
        return []
    try:
        history = _nzbget_request(url, username, password, "history", timeout_seconds=timeout_seconds)
    except Exception:
        return []
    groups = []
    if isinstance(history, dict):
        groups = history.get("History") or history.get("history") or []
    elif isinstance(history, list):
        groups = history
    out = []
    for item in groups:
        if not isinstance(item, dict):
            continue
        cat = str(item.get("Category") or "").strip()
        if category and cat != category:
            continue
        status = str(item.get("Status") or "").strip().upper()
        terminal_state = None
        if status in NZBGET_GROUP_STATUS_COMPLETED:
            terminal_state = "completed"
        elif status in NZBGET_GROUP_STATUS_FAILED:
            terminal_state = "failed"
        if not terminal_state:
            continue
        out.append({
            "id": str(item.get("NZBID") or "").strip() or None,
            "hash": str(item.get("NZBID") or "").strip() or None,
            "protocol": "usenet",
            "client_type": "nzbget",
            "status": status.lower(),
            "state": terminal_state,
            "state_reason": str(item.get("Status") or "").strip() or None,
            "path": str(item.get("DestDir") or "").strip(),
            "name": str(item.get("NZBName") or item.get("Name") or "").strip(),
        })
    return out


def list_completed_nzbget(url, username, password, category=None, timeout_seconds=15):
    return [item for item in list_history_nzbget(url, username, password, category=category, timeout_seconds=timeout_seconds) if item.get("state") == "completed"]


def remove_history_nzbget(url, username, password, item_id, timeout_seconds=15, delete_files=False):
    if not item_id:
        return False, "NZBGet item id is required."
    if not username:
        return False, "NZBGet username is required."
    if password is None:
        return False, "NZBGet password is required."
    try:
        # EditAction GroupAction "HistoryDelete" with IDs list
        result = _nzbget_request(
            url,
            username,
            password,
            "editqueue",
            params=["HistoryDelete", "", [int(item_id)]],
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        return False, str(exc)
    if not result:
        return False, "NZBGet failed to remove history entry."
    return True, "NZBGet history entry removed."


def remove_queue_item_nzbget(url, username, password, item_id, timeout_seconds=15, delete_files=False):
    if not item_id:
        return False, "NZBGet item id is required."
    if not username:
        return False, "NZBGet username is required."
    if password is None:
        return False, "NZBGet password is required."
    try:
        action = "GroupDelete" if delete_files else "GroupParkDelete"
        result = _nzbget_request(
            url,
            username,
            password,
            "editqueue",
            params=[action, "", [int(item_id)]],
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        return False, str(exc)
    if not result:
        return False, "NZBGet failed to remove queue item."
    return True, "NZBGet queue item removed."


def _nzbget_request(base_url, username, password, method, params=None, timeout_seconds=15):
    base = str(base_url or "").rstrip("/")
    if not base:
        raise ValueError("Client URL is required.")
    if not str(username or "").strip():
        raise ValueError("NZBGet username is required.")
    if password is None:
        raise ValueError("NZBGet password is required.")
    payload = {
        "version": "1.1",
        "method": str(method),
        "params": list(params or []),
        "id": 1,
    }
    response = requests.post(
        f"{base}/jsonrpc",
        json=payload,
        auth=(str(username), str(password)),
        headers={"User-Agent": DOWNLOADS_USER_AGENT},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    body = response.json() if response.content else {}
    if isinstance(body, dict) and body.get("error"):
        error = body.get("error")
        if isinstance(error, dict):
            raise RuntimeError(str(error.get("message") or error.get("code") or "NZBGet request failed."))
        raise RuntimeError(str(error))
    if not isinstance(body, dict):
        raise RuntimeError("Invalid NZBGet response.")
    return body.get("result")


def _nzbget_find_group_by_name(url, username, password, name, category=None, timeout_seconds=15):
    try:
        groups = _nzbget_request(url, username, password, "listgroups", timeout_seconds=timeout_seconds)
    except Exception:
        return None
    expected_name = str(name or "").strip().lower()
    expected_category = str(category or "").strip()
    for item in (groups or []):
        if not isinstance(item, dict):
            continue
        nzb_name = str(item.get("NZBName") or item.get("Name") or "").strip().lower()
        if expected_name and nzb_name != expected_name:
            continue
        if expected_category:
            cat = str(item.get("Category") or "").strip()
            if cat != expected_category:
                continue
        return item
    return None


def test_pneumatic(watch_folder, timeout_seconds=10):
    _ = timeout_seconds
    folder = str(watch_folder or "").strip()
    if not folder:
        return False, "Pneumatic watch folder is required in URL field."
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception as exc:
        return False, f"Pneumatic folder error: {exc}"
    if not os.path.isdir(folder):
        return False, "Pneumatic folder is not a directory."
    return True, f"Pneumatic OK ({folder})."


def add_pneumatic(watch_folder, download_url, timeout_seconds=15):
    folder = str(watch_folder or "").strip()
    if not folder:
        return False, "Pneumatic watch folder is required.", None
    os.makedirs(folder, exist_ok=True)
    stamp = int(time.time() * 1000)
    target = os.path.join(folder, f"aerofoil_{stamp}.nzb")
    try:
        resp = requests.get(download_url, timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
        if resp.status_code == 200 and resp.content:
            with open(target, "wb") as handle:
                handle.write(resp.content)
            return True, "Pneumatic wrote NZB file.", os.path.basename(target)
    except Exception:
        pass
    target = os.path.join(folder, f"aerofoil_{stamp}.nzburl")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(str(download_url or ""))
    return True, "Pneumatic wrote NZB URL file.", os.path.basename(target)


def _downloadstation_api_url(url):
    base = str(url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith("/webapi"):
        return base
    return f"{base}/webapi"


def _downloadstation_auth(url, username, password, timeout_seconds=10):
    api = _downloadstation_api_url(url)
    if not api:
        return False, "Client URL is required.", None
    params = {
        "api": "SYNO.API.Auth",
        "version": "6",
        "method": "login",
        "account": username or "",
        "passwd": password or "",
        "session": "DownloadStation",
        "format": "sid",
    }
    try:
        resp = requests.get(f"{api}/auth.cgi", params=params, timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
    except Exception as exc:
        return False, f"Download Station request failed: {exc}", None
    if resp.status_code != 200:
        return False, f"Download Station returned {resp.status_code}.", None
    payload = resp.json() if resp.content else {}
    if not payload.get("success"):
        return False, "Download Station authentication failed.", None
    sid = ((payload.get("data") or {}).get("sid") or "").strip()
    if not sid:
        return False, "Download Station sid not found.", None
    return True, None, sid


def _downloadstation_task(url, sid, method, timeout_seconds=15, extra=None):
    api = _downloadstation_api_url(url)
    params = {
        "api": "SYNO.DownloadStation.Task",
        "version": "1",
        "method": method,
        "_sid": sid,
    }
    params.update(dict(extra or {}))
    resp = requests.get(f"{api}/DownloadStation/task.cgi", params=params, timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
    if resp.status_code != 200:
        return False, f"Download Station returned {resp.status_code}.", None
    payload = resp.json() if resp.content else {}
    if not payload.get("success"):
        return False, "Download Station request failed.", None
    return True, None, payload.get("data") or {}


def test_downloadstation(url, username=None, password=None, timeout_seconds=10):
    ok, error, sid = _downloadstation_auth(url, username, password, timeout_seconds=timeout_seconds)
    if not ok:
        return False, error
    ok, error, _ = _downloadstation_task(url, sid, "list", timeout_seconds=timeout_seconds, extra={"additional": "detail"})
    if not ok:
        return False, error
    return True, "Download Station OK."


def add_downloadstation_nzb(url, username, password, download_url, category=None, timeout_seconds=15):
    _ = category
    ok, error, sid = _downloadstation_auth(url, username, password, timeout_seconds=timeout_seconds)
    if not ok:
        return False, error, None
    task_id = f"ds-{int(time.time() * 1000)}"
    ok, error, _data = _downloadstation_task(
        url,
        sid,
        "create",
        timeout_seconds=timeout_seconds,
        extra={"uri": download_url},
    )
    if not ok:
        return False, error, None
    return True, "Download Station accepted NZB.", task_id


def list_downloadstation(url, username, password, category=None, timeout_seconds=15):
    _ = category
    ok, error, sid = _downloadstation_auth(url, username, password, timeout_seconds=timeout_seconds)
    if not ok:
        logger.warning("Failed to load Download Station queue: %s", error)
        return []
    ok, error, data = _downloadstation_task(url, sid, "list", timeout_seconds=timeout_seconds, extra={"additional": "detail,transfer"})
    if not ok:
        logger.warning("Failed to load Download Station queue: %s", error)
        return []
    out = []
    for item in (data.get("tasks") or []):
        if str(item.get("type") or "").lower() not in ("nzb", "http", "ftp"):
            continue
        status_raw = str(item.get("status") or "").lower()
        size = _to_int(item.get("size"), 0)
        transfer = (item.get("additional") or {}).get("transfer") or {}
        downloaded = _to_int(transfer.get("size_downloaded"), 0)
        progress = (downloaded / size * 100.0) if size > 0 else _to_float(item.get("size_downloaded"), 0.0)
        mapped = "downloading"
        if status_raw in ("finished", "seeding"):
            mapped = "completed"
        elif status_raw in ("paused", "waiting"):
            mapped = "paused"
        elif status_raw in ("error",):
            mapped = "error"
        out.append({
            "id": str(item.get("id") or ""),
            "name": str(item.get("title") or item.get("id") or "").strip(),
            "status": mapped,
            "progress": max(0.0, min(100.0, progress)),
            "size": size,
            "downloaded": downloaded,
            "down_speed": _to_int(transfer.get("speed_download"), 0),
            "up_speed": _to_int(transfer.get("speed_upload"), 0),
            "eta": -1,
            "path": str(((item.get("additional") or {}).get("detail") or {}).get("destination") or ""),
            "category": None,
            "protocol": "usenet",
            "client_type": "downloadstation",
        })
    return out


def remove_downloadstation(url, username, password, item_id, timeout_seconds=15, delete_files=False):
    _ = delete_files
    ok, error, sid = _downloadstation_auth(url, username, password, timeout_seconds=timeout_seconds)
    if not ok:
        return False, error
    ok, error, _ = _downloadstation_task(url, sid, "delete", timeout_seconds=timeout_seconds, extra={"id": item_id, "force_complete": "false"})
    if not ok:
        return False, error
    return True, "Download Station task removed."


def _nzbvortex_api_url(url):
    base = str(url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith("/api"):
        return base
    return f"{base}/api"


def _nzbvortex_login(url, api_key, timeout_seconds=10):
    api = _nzbvortex_api_url(url)
    if not api:
        return False, "Client URL is required.", None
    nonce_resp = requests.get(f"{api}/auth/nonce", timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
    if nonce_resp.status_code != 200:
        return False, f"NZBVortex returned {nonce_resp.status_code}.", None
    nonce_payload = nonce_resp.json() if nonce_resp.content else {}
    nonce = str(nonce_payload.get("authNonce") or nonce_payload.get("nonce") or "").strip()
    if not nonce:
        return False, "NZBVortex nonce not found.", None
    cnonce = str(int(time.time() * 1000))
    hash_raw = f"{nonce}:{cnonce}:{api_key or ''}".encode("utf-8")
    digest = base64.b64encode(hashlib.sha256(hash_raw).digest()).decode("ascii")
    login = requests.get(
        f"{api}/auth/login",
        params={"nonce": nonce, "cnonce": cnonce, "hash": digest},
        timeout=timeout_seconds,
        headers={"User-Agent": DOWNLOADS_USER_AGENT},
    )
    if login.status_code != 200:
        return False, f"NZBVortex returned {login.status_code}.", None
    payload = login.json() if login.content else {}
    session_id = str(payload.get("sessionId") or payload.get("sessionid") or "").strip()
    if not session_id:
        return False, "NZBVortex authentication failed.", None
    return True, None, session_id


def test_nzbvortex(url, api_key, timeout_seconds=10):
    ok, error, sid = _nzbvortex_login(url, api_key, timeout_seconds=timeout_seconds)
    if not ok:
        return False, error
    api = _nzbvortex_api_url(url)
    resp = requests.get(f"{api}/app/appversion", params={"sessionid": sid}, timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
    if resp.status_code != 200:
        return False, f"NZBVortex returned {resp.status_code}."
    return True, "NZBVortex OK."


def add_nzbvortex(url, api_key, download_url, category=None, timeout_seconds=15):
    ok, error, sid = _nzbvortex_login(url, api_key, timeout_seconds=timeout_seconds)
    if not ok:
        return False, error, None
    api = _nzbvortex_api_url(url)
    try:
        nzb = requests.get(download_url, timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
    except Exception as exc:
        return False, str(exc), None
    if nzb.status_code != 200:
        return False, f"NZBVortex source download returned {nzb.status_code}.", None
    files = {"name": (f"aerofoil_{int(time.time()*1000)}.nzb", nzb.content, "application/x-nzb")}
    params = {"sessionid": sid, "priority": 0}
    if category:
        params["groupname"] = category
    resp = requests.post(f"{api}/nzb/add", params=params, files=files, timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
    if resp.status_code != 200:
        return False, f"NZBVortex returned {resp.status_code}.", None
    payload = resp.json() if resp.content else {}
    item_id = str(payload.get("id") or "").strip() or None
    return True, "NZBVortex accepted NZB.", item_id


def list_nzbvortex(url, api_key, category=None, timeout_seconds=15):
    ok, error, sid = _nzbvortex_login(url, api_key, timeout_seconds=timeout_seconds)
    if not ok:
        logger.warning("Failed to load NZBVortex queue: %s", error)
        return []
    api = _nzbvortex_api_url(url)
    params = {"sessionid": sid, "limitDone": 200}
    if category:
        params["groupName"] = category
    resp = requests.get(f"{api}/nzb", params=params, timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
    if resp.status_code != 200:
        logger.warning("Failed to load NZBVortex queue: status %s", resp.status_code)
        return []
    payload = resp.json() if resp.content else {}
    out = []
    for item in payload.get("items") or []:
        status_raw = str(item.get("state") or item.get("status") or "").lower()
        mapped = "downloading"
        if status_raw in ("done", "completed"):
            mapped = "completed"
        elif status_raw in ("paused", "stopped"):
            mapped = "paused"
        elif status_raw in ("error", "failed"):
            mapped = "error"
        out.append({
            "id": str(item.get("id") or ""),
            "name": str(item.get("name") or item.get("nzbName") or item.get("id") or ""),
            "status": mapped,
            "progress": _to_float(item.get("progress"), 0.0),
            "size": _to_int(item.get("size"), 0),
            "downloaded": _to_int(item.get("downloaded"), 0),
            "down_speed": _to_int(item.get("speed"), 0),
            "up_speed": 0,
            "eta": -1,
            "path": str(item.get("destination") or ""),
            "category": str(item.get("groupName") or ""),
            "protocol": "usenet",
            "client_type": "nzbvortex",
        })
    return out


def remove_nzbvortex(url, api_key, item_id, timeout_seconds=15, delete_files=False):
    ok, error, sid = _nzbvortex_login(url, api_key, timeout_seconds=timeout_seconds)
    if not ok:
        return False, error
    api = _nzbvortex_api_url(url)
    action = "cancelDelete" if delete_files else "cancel"
    resp = requests.get(f"{api}/nzb/{item_id}/{action}", params={"sessionid": sid}, timeout=timeout_seconds, headers={"User-Agent": DOWNLOADS_USER_AGENT})
    if resp.status_code != 200:
        return False, f"NZBVortex returned {resp.status_code}."
    return True, "NZBVortex item removed."


def _to_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default
