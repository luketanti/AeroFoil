from app.downloads.resolver import resolve_download_url
from app.downloads.torrent_client import (
    add_torrent,
    list_active as list_active_torrents,
    list_completed as list_completed_torrents,
    remove_torrent,
    test_torrent_client,
)
from app.downloads.usenet_client import (
    add_nzb,
    list_active as list_active_usenet,
    list_completed as list_completed_usenet,
    list_history as list_history_usenet,
    remove_history,
    remove_queue_item,
    test_sabnzbd,
)
from app.downloads.constants import (
    UNSUPPORTED_CLIENT_TYPE_MESSAGE,
    UNSUPPORTED_DOWNLOAD_PROTOCOL_MESSAGE,
)


TORRENT_CLIENT_TYPES = {"qbittorrent", "transmission", "deluge"}
USENET_CLIENT_TYPES = {"sabnzbd"}
DOWNLOAD_QUEUE_OPTION_KEYS = (
    "expected_name",
    "expected_update_number",
    "expected_version",
)


def _normalize_protocol_and_type(protocol, client_cfg):
    return (
        str(protocol or "").strip().lower(),
        str((client_cfg or {}).get("type") or "").strip().lower(),
    )


def _is_torrent_client(protocol, client_type):
    return protocol == "torrent" or client_type in TORRENT_CLIENT_TYPES


def _is_usenet_client(protocol, client_type):
    return protocol == "usenet" or client_type in USENET_CLIENT_TYPES


def _get_common_client_kwargs(client_cfg):
    config = client_cfg or {}
    return {
        "url": config.get("url"),
        "username": config.get("username"),
        "password": config.get("password"),
        "api_key": config.get("api_key"),
        "category": config.get("category"),
        "download_path": config.get("download_path"),
    }


def _get_queue_download_options(kwargs):
    options = {
        "update_only": bool(kwargs.get("update_only")),
        "exclude_russian": bool(kwargs.get("exclude_russian")),
    }
    for key in DOWNLOAD_QUEUE_OPTION_KEYS:
        options[key] = kwargs.get(key)
    return options


def test_download_client(client_type, url, username=None, password=None, api_key=None, timeout_seconds=10):
    client_type = str(client_type or "").strip().lower()
    if client_type in TORRENT_CLIENT_TYPES:
        return test_torrent_client(
            client_type=client_type,
            url=url,
            username=username,
            password=password,
            timeout_seconds=timeout_seconds,
        )
    if client_type == "sabnzbd":
        return test_sabnzbd(
            url=url,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
    return False, UNSUPPORTED_CLIENT_TYPE_MESSAGE


def queue_download(protocol, client_cfg, download_url, timeout_seconds=30, **kwargs):
    protocol, client_type = _normalize_protocol_and_type(protocol, client_cfg)
    common_kwargs = _get_common_client_kwargs(client_cfg)
    queue_options = _get_queue_download_options(kwargs)

    if _is_torrent_client(protocol, client_type):
        # Resolve Prowlarr URL to magnet or file content locally before passing to client
        # We give the resolver a bit more time if needed, but respect the overall timeout
        resolved_type, resolved_data = resolve_download_url(download_url, timeout=timeout_seconds)
        return add_torrent(
            client_type=client_type,
            url=common_kwargs["url"],
            username=common_kwargs["username"],
            password=common_kwargs["password"],
            download_url=resolved_data if resolved_type in ("url", "magnet") else None,
            torrent_content=resolved_data if resolved_type == "torrent_content" else None,
            category=common_kwargs["category"],
            download_path=common_kwargs["download_path"],
            timeout_seconds=timeout_seconds,
            **queue_options,
        )
    if _is_usenet_client(protocol, client_type):
        return add_nzb(
            url=common_kwargs["url"],
            api_key=common_kwargs["api_key"],
            download_url=download_url,
            category=common_kwargs["category"],
            timeout_seconds=timeout_seconds,
            **queue_options,
        )
    return False, UNSUPPORTED_DOWNLOAD_PROTOCOL_MESSAGE, None



def list_active_downloads(protocol, client_cfg, timeout_seconds=15):
    protocol, client_type = _normalize_protocol_and_type(protocol, client_cfg)
    common_kwargs = _get_common_client_kwargs(client_cfg)
    if _is_torrent_client(protocol, client_type):
        items = list_active_torrents(
            client_type=client_type,
            url=common_kwargs["url"],
            username=common_kwargs["username"],
            password=common_kwargs["password"],
            category=common_kwargs["category"],
            download_path=common_kwargs["download_path"],
            timeout_seconds=timeout_seconds,
        )
        for item in items:
            item.setdefault("protocol", "torrent")
            item.setdefault("client_type", client_type)
        return items
    if _is_usenet_client(protocol, client_type):
        return list_active_usenet(
            url=common_kwargs["url"],
            api_key=common_kwargs["api_key"],
            category=common_kwargs["category"],
            timeout_seconds=timeout_seconds,
        )
    return []


def list_completed_downloads(protocol, client_cfg, timeout_seconds=15):
    protocol, client_type = _normalize_protocol_and_type(protocol, client_cfg)
    common_kwargs = _get_common_client_kwargs(client_cfg)
    if _is_torrent_client(protocol, client_type):
        items = list_completed_torrents(
            client_type=client_type,
            url=common_kwargs["url"],
            username=common_kwargs["username"],
            password=common_kwargs["password"],
            category=common_kwargs["category"],
            download_path=common_kwargs["download_path"],
            timeout_seconds=timeout_seconds,
        )
        for item in items:
            item.setdefault("protocol", "torrent")
            item.setdefault("client_type", client_type)
        return items
    if _is_usenet_client(protocol, client_type):
        return list_completed_usenet(
            url=common_kwargs["url"],
            api_key=common_kwargs["api_key"],
            category=common_kwargs["category"],
            timeout_seconds=timeout_seconds,
        )
    return []


def list_history_downloads(protocol, client_cfg, timeout_seconds=15):
    protocol = str(protocol or "").strip().lower()
    client_type = str((client_cfg or {}).get("type") or "").strip().lower()
    if protocol == "usenet" or client_type in USENET_CLIENT_TYPES:
        return list_history_usenet(
            url=(client_cfg or {}).get("url"),
            api_key=(client_cfg or {}).get("api_key"),
            category=(client_cfg or {}).get("category"),
            timeout_seconds=timeout_seconds,
        )
    return list_completed_downloads(protocol, client_cfg, timeout_seconds=timeout_seconds)


def remove_completed_download(protocol, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    protocol, client_type = _normalize_protocol_and_type(protocol, client_cfg)
    common_kwargs = _get_common_client_kwargs(client_cfg)
    if _is_torrent_client(protocol, client_type):
        return remove_torrent(
            client_type=client_type,
            url=common_kwargs["url"],
            username=common_kwargs["username"],
            password=common_kwargs["password"],
            torrent_hash=item_id,
            timeout_seconds=timeout_seconds,
            delete_files=delete_files,
        )
    if _is_usenet_client(protocol, client_type):
        return remove_history(
            url=common_kwargs["url"],
            api_key=common_kwargs["api_key"],
            item_id=item_id,
            timeout_seconds=timeout_seconds,
            delete_files=delete_files,
        )
    return False, UNSUPPORTED_DOWNLOAD_PROTOCOL_MESSAGE


def remove_active_download(protocol, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    protocol, client_type = _normalize_protocol_and_type(protocol, client_cfg)
    common_kwargs = _get_common_client_kwargs(client_cfg)
    if _is_torrent_client(protocol, client_type):
        return remove_torrent(
            client_type=client_type,
            url=common_kwargs["url"],
            username=common_kwargs["username"],
            password=common_kwargs["password"],
            torrent_hash=item_id,
            timeout_seconds=timeout_seconds,
            delete_files=delete_files,
        )
    if _is_usenet_client(protocol, client_type):
        return remove_queue_item(
            url=common_kwargs["url"],
            api_key=common_kwargs["api_key"],
            item_id=item_id,
            timeout_seconds=timeout_seconds,
            delete_files=delete_files,
        )
    return False, UNSUPPORTED_DOWNLOAD_PROTOCOL_MESSAGE
