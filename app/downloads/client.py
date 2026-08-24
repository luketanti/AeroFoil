from dataclasses import dataclass
from typing import Callable

from app.downloads.constants import (
    UNSUPPORTED_CLIENT_TYPE_MESSAGE,
    UNSUPPORTED_DOWNLOAD_PROTOCOL_MESSAGE,
)
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
    add_downloadstation_nzb,
    add_nzbget,
    add_nzbvortex,
    add_pneumatic,
    list_active as list_active_usenet,
    list_downloadstation,
    list_active_nzbget,
    list_nzbvortex,
    list_completed as list_completed_usenet,
    list_completed_nzbget,
    list_history as list_history_usenet,
    list_history_nzbget,
    remove_history,
    remove_downloadstation,
    remove_history_nzbget,
    remove_nzbvortex,
    remove_queue_item,
    remove_queue_item_nzbget,
    test_downloadstation,
    test_nzbvortex,
    test_pneumatic,
    test_sabnzbd,
    test_nzbget,
)


DOWNLOAD_QUEUE_OPTION_KEYS = (
    "expected_name",
    "expected_update_number",
    "expected_version",
    "dlc_only",
)


@dataclass(frozen=True)
class DownloadClientAdapter:
    protocol: str
    client_type: str
    implemented: bool
    supports_categories: bool
    supports_download_path: bool
    supports_delete_files: bool
    supports_history: bool
    test_fn: Callable
    queue_fn: Callable
    list_active_fn: Callable
    list_completed_fn: Callable
    list_history_fn: Callable
    remove_active_fn: Callable
    remove_completed_fn: Callable


def _normalize_protocol_and_type(protocol, client_cfg):
    return (
        str(protocol or "").strip().lower(),
        str((client_cfg or {}).get("type") or "").strip().lower(),
    )


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


def _queue_torrent(client_type, client_cfg, download_url, timeout_seconds=15, **kwargs):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    queue_options = _get_queue_download_options(kwargs)
    resolved_type, resolved_data = resolve_download_url(download_url, timeout=timeout_seconds)
    effective_url = resolved_data if resolved_type in ("url", "magnet") else download_url
    torrent_content = resolved_data if resolved_type == "torrent_content" else None
    return add_torrent(
        client_type=client_type,
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        download_url=effective_url,
        torrent_content=torrent_content,
        category=common_kwargs["category"],
        download_path=common_kwargs["download_path"],
        timeout_seconds=timeout_seconds,
        **queue_options,
    )


def _list_active_torrent(client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
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


def _list_completed_torrent(client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
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


def _remove_torrent(client_type, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return remove_torrent(
        client_type=client_type,
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        torrent_hash=item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )


def _test_torrent(client_type, url, username=None, password=None, timeout_seconds=10, **_kwargs):
    return test_torrent_client(
        client_type=client_type,
        url=url,
        username=username,
        password=password,
        timeout_seconds=timeout_seconds,
    )


def _queue_sabnzbd(_client_type, client_cfg, download_url, timeout_seconds=15, **kwargs):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    queue_options = _get_queue_download_options(kwargs)
    return add_nzb(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        download_url=download_url,
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
        **queue_options,
    )


def _list_active_sabnzbd(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return list_active_usenet(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    )


def _list_completed_sabnzbd(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return list_completed_usenet(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    )


def _list_history_sabnzbd(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return list_history_usenet(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    )


def _remove_active_sabnzbd(_client_type, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return remove_queue_item(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        item_id=item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )


def _remove_completed_sabnzbd(_client_type, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return remove_history(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        item_id=item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )


def _test_sabnzbd(_client_type, url, api_key=None, timeout_seconds=10, **_kwargs):
    return test_sabnzbd(
        url=url,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
    )


def _queue_nzbget(_client_type, client_cfg, download_url, timeout_seconds=15, **kwargs):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    queue_options = _get_queue_download_options(kwargs)
    return add_nzbget(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        download_url=download_url,
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
        **queue_options,
    )


def _list_active_nzbget(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return list_active_nzbget(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    )


def _list_completed_nzbget(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return list_completed_nzbget(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    )


def _list_history_nzbget(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return list_history_nzbget(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    )


def _remove_active_nzbget(_client_type, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return remove_queue_item_nzbget(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        item_id=item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )


def _remove_completed_nzbget(_client_type, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return remove_history_nzbget(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        item_id=item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )


def _test_nzbget(_client_type, url, username=None, password=None, timeout_seconds=10, **_kwargs):
    return test_nzbget(
        url=url,
        username=username,
        password=password,
        timeout_seconds=timeout_seconds,
    )


def _queue_pneumatic(_client_type, client_cfg, download_url, timeout_seconds=15, **_kwargs):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return add_pneumatic(
        watch_folder=common_kwargs["url"],
        download_url=download_url,
        timeout_seconds=timeout_seconds,
    )


def _test_pneumatic_client(_client_type, url, timeout_seconds=10, **_kwargs):
    return test_pneumatic(
        watch_folder=url,
        timeout_seconds=timeout_seconds,
    )


def _queue_downloadstation_usenet(_client_type, client_cfg, download_url, timeout_seconds=15, **_kwargs):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return add_downloadstation_nzb(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        download_url=download_url,
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    )


def _list_active_downloadstation_usenet(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return [item for item in list_downloadstation(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    ) if item.get("status") != "completed"]


def _list_completed_downloadstation_usenet(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return [item for item in list_downloadstation(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    ) if item.get("status") == "completed"]


def _remove_downloadstation_usenet(_client_type, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return remove_downloadstation(
        url=common_kwargs["url"],
        username=common_kwargs["username"],
        password=common_kwargs["password"],
        item_id=item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )


def _test_downloadstation_usenet(_client_type, url, username=None, password=None, timeout_seconds=10, **_kwargs):
    return test_downloadstation(
        url=url,
        username=username,
        password=password,
        timeout_seconds=timeout_seconds,
    )


def _queue_nzbvortex(_client_type, client_cfg, download_url, timeout_seconds=15, **_kwargs):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return add_nzbvortex(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        download_url=download_url,
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    )


def _list_active_nzbvortex(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return [item for item in list_nzbvortex(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    ) if item.get("status") != "completed"]


def _list_completed_nzbvortex(_client_type, client_cfg, timeout_seconds=15):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return [item for item in list_nzbvortex(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        category=common_kwargs["category"],
        timeout_seconds=timeout_seconds,
    ) if item.get("status") == "completed"]


def _remove_nzbvortex(_client_type, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    common_kwargs = _get_common_client_kwargs(client_cfg)
    return remove_nzbvortex(
        url=common_kwargs["url"],
        api_key=common_kwargs["api_key"],
        item_id=item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )


def _test_nzbvortex_client(_client_type, url, api_key=None, timeout_seconds=10, **_kwargs):
    return test_nzbvortex(
        url=url,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
    )


def _unsupported_test(client_type, url=None, **_kwargs):
    _ = url
    return False, f"{client_type} is listed by Sonarr but is not implemented in AeroFoil yet."


def _unsupported_queue(client_type, _client_cfg, _download_url, **_kwargs):
    return False, f"{client_type} is listed by Sonarr but is not implemented in AeroFoil yet.", None


def _unsupported_list(_client_type, _client_cfg, **_kwargs):
    return []


def _unsupported_remove(client_type, _client_cfg, _item_id, **_kwargs):
    return False, f"{client_type} is listed by Sonarr but is not implemented in AeroFoil yet."


def _supports_live_status(adapter):
    if not adapter:
        return False
    return not (
        adapter.list_active_fn is _unsupported_list
        and adapter.list_completed_fn is _unsupported_list
        and adapter.list_history_fn is _unsupported_list
    )


_ADAPTERS = {
    ("torrent", "qbittorrent"): DownloadClientAdapter(
        protocol="torrent",
        client_type="qbittorrent",
        implemented=True,
        supports_categories=True,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "transmission"): DownloadClientAdapter(
        protocol="torrent",
        client_type="transmission",
        implemented=True,
        supports_categories=True,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "deluge"): DownloadClientAdapter(
        protocol="torrent",
        client_type="deluge",
        implemented=True,
        supports_categories=True,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "rtorrent"): DownloadClientAdapter(
        protocol="torrent",
        client_type="rtorrent",
        implemented=True,
        supports_categories=True,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("usenet", "sabnzbd"): DownloadClientAdapter(
        protocol="usenet",
        client_type="sabnzbd",
        implemented=True,
        supports_categories=True,
        supports_download_path=False,
        supports_delete_files=True,
        supports_history=True,
        test_fn=_test_sabnzbd,
        queue_fn=_queue_sabnzbd,
        list_active_fn=_list_active_sabnzbd,
        list_completed_fn=_list_completed_sabnzbd,
        list_history_fn=_list_history_sabnzbd,
        remove_active_fn=_remove_active_sabnzbd,
        remove_completed_fn=_remove_completed_sabnzbd,
    ),
    ("usenet", "nzbget"): DownloadClientAdapter(
        protocol="usenet",
        client_type="nzbget",
        implemented=True,
        supports_categories=True,
        supports_download_path=False,
        supports_delete_files=True,
        supports_history=True,
        test_fn=_test_nzbget,
        queue_fn=_queue_nzbget,
        list_active_fn=_list_active_nzbget,
        list_completed_fn=_list_completed_nzbget,
        list_history_fn=_list_history_nzbget,
        remove_active_fn=_remove_active_nzbget,
        remove_completed_fn=_remove_completed_nzbget,
    ),
    ("torrent", "aria2"): DownloadClientAdapter(
        protocol="torrent",
        client_type="aria2",
        implemented=True,
        supports_categories=False,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "blackhole"): DownloadClientAdapter(
        protocol="torrent",
        client_type="blackhole",
        implemented=True,
        supports_categories=False,
        supports_download_path=True,
        supports_delete_files=False,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "downloadstation"): DownloadClientAdapter(
        protocol="torrent",
        client_type="downloadstation",
        implemented=True,
        supports_categories=True,
        supports_download_path=False,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "flood"): DownloadClientAdapter(
        protocol="torrent",
        client_type="flood",
        implemented=True,
        supports_categories=True,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "freeboxdownload"): DownloadClientAdapter(
        protocol="torrent",
        client_type="freeboxdownload",
        implemented=True,
        supports_categories=False,
        supports_download_path=False,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "hadouken"): DownloadClientAdapter(
        protocol="torrent",
        client_type="hadouken",
        implemented=True,
        supports_categories=False,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "rqbit"): DownloadClientAdapter(
        protocol="torrent",
        client_type="rqbit",
        implemented=True,
        supports_categories=False,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "tribler"): DownloadClientAdapter(
        protocol="torrent",
        client_type="tribler",
        implemented=True,
        supports_categories=False,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "utorrent"): DownloadClientAdapter(
        protocol="torrent",
        client_type="utorrent",
        implemented=True,
        supports_categories=True,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("torrent", "vuze"): DownloadClientAdapter(
        protocol="torrent",
        client_type="vuze",
        implemented=True,
        supports_categories=True,
        supports_download_path=True,
        supports_delete_files=True,
        supports_history=False,
        test_fn=_test_torrent,
        queue_fn=_queue_torrent,
        list_active_fn=_list_active_torrent,
        list_completed_fn=_list_completed_torrent,
        list_history_fn=_list_completed_torrent,
        remove_active_fn=_remove_torrent,
        remove_completed_fn=_remove_torrent,
    ),
    ("usenet", "downloadstation"): DownloadClientAdapter(
        protocol="usenet",
        client_type="downloadstation",
        implemented=True,
        supports_categories=True,
        supports_download_path=False,
        supports_delete_files=True,
        supports_history=True,
        test_fn=_test_downloadstation_usenet,
        queue_fn=_queue_downloadstation_usenet,
        list_active_fn=_list_active_downloadstation_usenet,
        list_completed_fn=_list_completed_downloadstation_usenet,
        list_history_fn=_list_completed_downloadstation_usenet,
        remove_active_fn=_remove_downloadstation_usenet,
        remove_completed_fn=_remove_downloadstation_usenet,
    ),
    ("usenet", "nzbvortex"): DownloadClientAdapter(
        protocol="usenet",
        client_type="nzbvortex",
        implemented=True,
        supports_categories=True,
        supports_download_path=False,
        supports_delete_files=True,
        supports_history=True,
        test_fn=_test_nzbvortex_client,
        queue_fn=_queue_nzbvortex,
        list_active_fn=_list_active_nzbvortex,
        list_completed_fn=_list_completed_nzbvortex,
        list_history_fn=_list_completed_nzbvortex,
        remove_active_fn=_remove_nzbvortex,
        remove_completed_fn=_remove_nzbvortex,
    ),
    ("usenet", "pneumatic"): DownloadClientAdapter(
        protocol="usenet",
        client_type="pneumatic",
        implemented=True,
        supports_categories=False,
        supports_download_path=False,
        supports_delete_files=False,
        supports_history=False,
        test_fn=_test_pneumatic_client,
        queue_fn=_queue_pneumatic,
        list_active_fn=_unsupported_list,
        list_completed_fn=_unsupported_list,
        list_history_fn=_unsupported_list,
        remove_active_fn=_unsupported_remove,
        remove_completed_fn=_unsupported_remove,
    ),
}


TORRENT_CLIENT_TYPES = {
    key[1] for key in _ADAPTERS.keys() if key[0] == "torrent"
}
USENET_CLIENT_TYPES = {
    key[1] for key in _ADAPTERS.keys() if key[0] == "usenet"
}


def _get_adapter(protocol, client_type):
    return _ADAPTERS.get((str(protocol or "").strip().lower(), str(client_type or "").strip().lower()))


def _resolve_adapter(protocol, client_cfg):
    protocol, client_type = _normalize_protocol_and_type(protocol, client_cfg)
    adapter = _get_adapter(protocol, client_type)
    if adapter:
        return adapter
    if protocol == "torrent":
        return _get_adapter("torrent", client_type)
    if protocol == "usenet":
        return _get_adapter("usenet", client_type)
    if client_type in TORRENT_CLIENT_TYPES:
        return _get_adapter("torrent", client_type)
    if client_type in USENET_CLIENT_TYPES:
        return _get_adapter("usenet", client_type)
    return None


def get_supported_download_clients():
    out = []
    for adapter in _ADAPTERS.values():
        out.append({
            "protocol": adapter.protocol,
            "type": adapter.client_type,
            "implemented": bool(adapter.implemented),
            "supports_categories": bool(adapter.supports_categories),
            "supports_download_path": bool(adapter.supports_download_path),
            "supports_delete_files": bool(adapter.supports_delete_files),
            "supports_history": bool(adapter.supports_history),
            "supports_live_status": bool(_supports_live_status(adapter)),
        })
    out.sort(key=lambda item: (item["protocol"], item["type"]))
    return out


def get_download_client_capabilities(protocol, client_cfg):
    adapter = _resolve_adapter(protocol, client_cfg)
    if not adapter:
        return None
    return {
        "protocol": adapter.protocol,
        "type": adapter.client_type,
        "implemented": bool(adapter.implemented),
        "supports_categories": bool(adapter.supports_categories),
        "supports_download_path": bool(adapter.supports_download_path),
        "supports_delete_files": bool(adapter.supports_delete_files),
        "supports_history": bool(adapter.supports_history),
        "supports_live_status": bool(_supports_live_status(adapter)),
    }


def get_download_client_diagnostics(protocol, client_cfg):
    client_cfg = client_cfg or {}
    adapter = _resolve_adapter(protocol, client_cfg)
    if not adapter:
        return {
            "supported": False,
            "protocol": str(protocol or "").strip().lower() or None,
            "type": str(client_cfg.get("type") or "").strip().lower() or None,
            "missing": [],
            "capabilities": None,
        }

    capabilities = get_download_client_capabilities(adapter.protocol, {"type": adapter.client_type})
    if not adapter.implemented:
        return {
            "supported": False,
            "protocol": adapter.protocol,
            "type": adapter.client_type,
            "missing": [],
            "capabilities": capabilities,
            "reason": "client_not_implemented",
        }
    missing = []
    if not str(client_cfg.get("url") or "").strip():
        missing.append("url")

    if adapter.protocol == "usenet":
        if adapter.client_type == "sabnzbd":
            if not str(client_cfg.get("api_key") or "").strip():
                missing.append("api_key")
        elif adapter.client_type == "nzbget":
            if not str(client_cfg.get("username") or "").strip():
                missing.append("username")
            if client_cfg.get("password") is None or str(client_cfg.get("password")).strip() == "":
                missing.append("password")
        elif adapter.client_type == "nzbvortex":
            if not str(client_cfg.get("api_key") or "").strip():
                missing.append("api_key")
        elif adapter.client_type == "pneumatic":
            pass
        else:
            missing.append("username")
            if client_cfg.get("password") is None or str(client_cfg.get("password")).strip() == "":
                missing.append("password")
    else:
        if adapter.client_type == "tribler":
            if client_cfg.get("password") is None or str(client_cfg.get("password")).strip() == "":
                missing.append("password")
        elif adapter.client_type not in ("deluge", "aria2", "rqbit", "blackhole") and not str(client_cfg.get("username") or "").strip():
            missing.append("username")
        if adapter.client_type not in ("blackhole", "aria2", "rqbit"):
            if not str(client_cfg.get("password") or "").strip():
                missing.append("password")

    return {
        "supported": True,
        "protocol": adapter.protocol,
        "type": adapter.client_type,
        "missing": missing,
        "capabilities": capabilities,
    }


def test_download_client(client_type, url, username=None, password=None, api_key=None, timeout_seconds=10):
    client_type = str(client_type or "").strip().lower()
    adapter = _get_adapter("torrent", client_type) or _get_adapter("usenet", client_type)
    if not adapter:
        return False, UNSUPPORTED_CLIENT_TYPE_MESSAGE
    return adapter.test_fn(
        client_type,
        url=url,
        username=username,
        password=password,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
    )


def queue_download(protocol, client_cfg, download_url, timeout_seconds=15, **kwargs):
    adapter = _resolve_adapter(protocol, client_cfg)
    if not adapter:
        return False, UNSUPPORTED_DOWNLOAD_PROTOCOL_MESSAGE, None
    return adapter.queue_fn(
        adapter.client_type,
        client_cfg,
        download_url,
        timeout_seconds=timeout_seconds,
        **kwargs,
    )


def list_active_downloads(protocol, client_cfg, timeout_seconds=15):
    adapter = _resolve_adapter(protocol, client_cfg)
    if not adapter:
        return []
    return adapter.list_active_fn(adapter.client_type, client_cfg, timeout_seconds=timeout_seconds)


def list_completed_downloads(protocol, client_cfg, timeout_seconds=15):
    adapter = _resolve_adapter(protocol, client_cfg)
    if not adapter:
        return []
    return adapter.list_completed_fn(adapter.client_type, client_cfg, timeout_seconds=timeout_seconds)


def list_history_downloads(protocol, client_cfg, timeout_seconds=15):
    adapter = _resolve_adapter(protocol, client_cfg)
    if not adapter:
        return []
    return adapter.list_history_fn(adapter.client_type, client_cfg, timeout_seconds=timeout_seconds)


def remove_completed_download(protocol, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    adapter = _resolve_adapter(protocol, client_cfg)
    if not adapter:
        return False, UNSUPPORTED_DOWNLOAD_PROTOCOL_MESSAGE
    return adapter.remove_completed_fn(
        adapter.client_type,
        client_cfg,
        item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )


def remove_active_download(protocol, client_cfg, item_id, timeout_seconds=15, delete_files=False):
    adapter = _resolve_adapter(protocol, client_cfg)
    if not adapter:
        return False, UNSUPPORTED_DOWNLOAD_PROTOCOL_MESSAGE
    return adapter.remove_active_fn(
        adapter.client_type,
        client_cfg,
        item_id,
        timeout_seconds=timeout_seconds,
        delete_files=delete_files,
    )
