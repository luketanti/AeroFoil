from app.downloads.torrent_client import (
    add_torrent,
    list_active as list_active_torrents,
    list_completed as list_completed_torrents,
    remove_torrent,
    test_torrent_client,
)
from app.downloads.usenet_client import add_nzb, list_active as list_active_usenet, list_completed as list_completed_usenet, remove_history, test_sabnzbd


TORRENT_CLIENT_TYPES = {"qbittorrent", "transmission", "deluge"}
USENET_CLIENT_TYPES = {"sabnzbd"}


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
    return False, "Unsupported client type."


def queue_download(protocol, client_cfg, download_url, timeout_seconds=15, **kwargs):
    protocol = str(protocol or "").strip().lower()
    client_type = str((client_cfg or {}).get("type") or "").strip().lower()
    if protocol == "torrent" or client_type in TORRENT_CLIENT_TYPES:
        return add_torrent(
            client_type=client_type,
            url=(client_cfg or {}).get("url"),
            username=(client_cfg or {}).get("username"),
            password=(client_cfg or {}).get("password"),
            download_url=download_url,
            category=(client_cfg or {}).get("category"),
            download_path=(client_cfg or {}).get("download_path"),
            timeout_seconds=timeout_seconds,
            expected_name=kwargs.get("expected_name"),
            update_only=bool(kwargs.get("update_only")),
            exclude_russian=bool(kwargs.get("exclude_russian")),
            expected_update_number=kwargs.get("expected_update_number"),
            expected_version=kwargs.get("expected_version"),
        )
    if protocol == "usenet" or client_type in USENET_CLIENT_TYPES:
        return add_nzb(
            url=(client_cfg or {}).get("url"),
            api_key=(client_cfg or {}).get("api_key"),
            download_url=download_url,
            category=(client_cfg or {}).get("category"),
            timeout_seconds=timeout_seconds,
            expected_name=kwargs.get("expected_name"),
            update_only=bool(kwargs.get("update_only")),
            exclude_russian=bool(kwargs.get("exclude_russian")),
            expected_update_number=kwargs.get("expected_update_number"),
            expected_version=kwargs.get("expected_version"),
        )
    return False, "Unsupported download protocol.", None


def list_active_downloads(protocol, client_cfg, timeout_seconds=15):
    protocol = str(protocol or "").strip().lower()
    client_type = str((client_cfg or {}).get("type") or "").strip().lower()
    if protocol == "torrent" or client_type in TORRENT_CLIENT_TYPES:
        items = list_active_torrents(
            client_type=client_type,
            url=(client_cfg or {}).get("url"),
            username=(client_cfg or {}).get("username"),
            password=(client_cfg or {}).get("password"),
            category=(client_cfg or {}).get("category"),
            download_path=(client_cfg or {}).get("download_path"),
            timeout_seconds=timeout_seconds,
        )
        for item in items:
            item.setdefault("protocol", "torrent")
            item.setdefault("client_type", client_type)
        return items
    if protocol == "usenet" or client_type in USENET_CLIENT_TYPES:
        return list_active_usenet(
            url=(client_cfg or {}).get("url"),
            api_key=(client_cfg or {}).get("api_key"),
            category=(client_cfg or {}).get("category"),
            timeout_seconds=timeout_seconds,
        )
    return []


def list_completed_downloads(protocol, client_cfg, timeout_seconds=15):
    protocol = str(protocol or "").strip().lower()
    client_type = str((client_cfg or {}).get("type") or "").strip().lower()
    if protocol == "torrent" or client_type in TORRENT_CLIENT_TYPES:
        items = list_completed_torrents(
            client_type=client_type,
            url=(client_cfg or {}).get("url"),
            username=(client_cfg or {}).get("username"),
            password=(client_cfg or {}).get("password"),
            category=(client_cfg or {}).get("category"),
            download_path=(client_cfg or {}).get("download_path"),
            timeout_seconds=timeout_seconds,
        )
        for item in items:
            item.setdefault("protocol", "torrent")
            item.setdefault("client_type", client_type)
        return items
    if protocol == "usenet" or client_type in USENET_CLIENT_TYPES:
        return list_completed_usenet(
            url=(client_cfg or {}).get("url"),
            api_key=(client_cfg or {}).get("api_key"),
            category=(client_cfg or {}).get("category"),
            timeout_seconds=timeout_seconds,
        )
    return []


def remove_completed_download(protocol, client_cfg, item_id, timeout_seconds=15):
    protocol = str(protocol or "").strip().lower()
    client_type = str((client_cfg or {}).get("type") or "").strip().lower()
    if protocol == "torrent" or client_type in TORRENT_CLIENT_TYPES:
        return remove_torrent(
            client_type=client_type,
            url=(client_cfg or {}).get("url"),
            username=(client_cfg or {}).get("username"),
            password=(client_cfg or {}).get("password"),
            torrent_hash=item_id,
            timeout_seconds=timeout_seconds,
        )
    if protocol == "usenet" or client_type in USENET_CLIENT_TYPES:
        return remove_history(
            url=(client_cfg or {}).get("url"),
            api_key=(client_cfg or {}).get("api_key"),
            item_id=item_id,
            timeout_seconds=timeout_seconds,
        )
    return False, "Unsupported download protocol."
