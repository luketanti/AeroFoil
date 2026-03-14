import logging
import time

import requests

from app.downloads.torrent_client import _select_update_file_indices

logger = logging.getLogger("downloads.sabnzbd")

DOWNLOADS_USER_AGENT = "AeroFoil/Downloads"


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
    exclude_russian=False,
    expected_update_number=None,
    expected_version=None,
):
    if not download_url:
        return False, "Download URL is required.", None
    if not api_key:
        return False, "SABnzbd API key is required.", None
    try:
        priority = -2 if update_only else None
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
        if update_only and nzo_id:
            ok, message = _restrict_job_to_matching_update_files(
                url,
                api_key,
                nzo_id,
                timeout_seconds=timeout_seconds,
                exclude_russian=exclude_russian,
                expected_update_number=expected_update_number,
                expected_version=expected_version,
            )
            if not ok:
                _delete_job(url, api_key, nzo_id, timeout_seconds=timeout_seconds)
                return False, message, None
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


def list_completed(url, api_key, category=None, timeout_seconds=15):
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
    completed = []
    for item in slots:
        if not isinstance(item, dict):
            continue
        item_category = str(item.get("category") or item.get("cat") or "").strip()
        if category and item_category != category:
            continue
        status = str(item.get("status") or "").lower()
        completed_flag = str(item.get("completed") or "").lower()
        if status not in ("completed", "complete") and completed_flag not in ("1", "true", "yes"):
            continue
        nzo_id = str(item.get("nzo_id") or "").strip() or None
        path = item.get("storage") or item.get("path") or item.get("downloaded_path") or ""
        path = str(path or "").strip()
        if not path:
            # Avoid treating the global completed_dir as a per-job path.
            continue
        completed.append({
            "id": nzo_id,
            "hash": nzo_id,
            "protocol": "usenet",
            "client_type": "sabnzbd",
            "path": path,
            "name": item.get("name") or item.get("nzb_name") or item.get("filename") or "",
        })
    return completed


def remove_history(url, api_key, item_id, timeout_seconds=15):
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
            del_files=0,
            output="json",
        )
    except Exception as exc:
        return False, str(exc)
    status = payload.get("status")
    if status in (True, "true", "True", 1, "1"):
        return True, "SABnzbd history entry removed."
    message = payload.get("error") or payload.get("message") or "SABnzbd failed to remove history entry."
    return False, str(message)


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


def _delete_job(url, api_key, nzo_id, timeout_seconds=15):
    try:
        _sab_request(
            url,
            api_key,
            mode="queue",
            timeout_seconds=timeout_seconds,
            name="delete",
            value=nzo_id,
            del_files=0,
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
    files = []
    for _ in range(10):
        files = _get_job_files(url, api_key, nzo_id, timeout_seconds=timeout_seconds)
        if files:
            break
        time.sleep(1)
    if not files:
        return False, "Unable to resolve SABnzbd file list for update selection."

    file_names = [str(item.get("filename") or "") for item in files]
    keep_indices = _select_update_file_indices(
        file_names,
        expected_update_number=expected_update_number,
        expected_version=expected_version,
        exclude_russian=exclude_russian,
    )
    if not keep_indices:
        return False, "No matching update version found in NZB."

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
