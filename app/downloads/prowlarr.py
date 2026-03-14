import logging
import re
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests

logger = logging.getLogger("downloads.prowlarr")


class ProwlarrClient:
    def __init__(self, base_url, api_key, timeout_seconds=15):
        self.base_url = base_url.rstrip("/") + "/"
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def _headers(self):
        return {"X-Api-Key": self.api_key}

    def _get(self, path, params=None):
        url = urljoin(self.base_url, path.lstrip("/"))
        resp = requests.get(
            url,
            headers=self._headers(),
            params=params or {},
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def system_status(self):
        return self._get("/api/v1/system/status")

    def list_indexers(self):
        return self._get("/api/v1/indexer")

    def search(self, query, indexer_ids=None, categories=None, limit=None):
        params = {"query": query, "type": "search"}
        if indexer_ids:
            normalized_ids = []
            for item in indexer_ids:
                if isinstance(item, int):
                    normalized_ids.append(int(item))
                    continue
                if isinstance(item, str):
                    value = item.strip()
                    if value.isdigit():
                        normalized_ids.append(int(value))
            if normalized_ids:
                # Prowlarr expects repeated query params (indexerIds=1&indexerIds=2),
                # not a single comma-separated value.
                params["indexerIds"] = normalized_ids
        if categories:
            normalized = []
            for item in categories:
                if isinstance(item, int):
                    normalized.append(int(item))
                    continue
                if isinstance(item, str):
                    value = item.strip()
                    if value.isdigit():
                        normalized.append(int(value))
            if normalized:
                params["categories"] = normalized
        resolved_limit = 100 if limit is None else max(int(limit), 1)
        params["limit"] = resolved_limit
        results = self._get("/api/v1/search", params=params)
        normalized = [_normalize_result(item) for item in results or []]
        if limit is not None:
            return normalized[:limit]
        return normalized


def _normalize_result(item):
    protocol = _normalize_protocol(item)
    age_minutes = _extract_age_minutes(item)
    return {
        "title": item.get("title") or "",
        "size": int(item.get("size") or 0),
        "seeders": int(item.get("seeders") or 0),
        "leechers": int(item.get("leechers") or 0),
        "download_url": item.get("downloadUrl") or "",
        "info_url": item.get("infoUrl") or "",
        "indexer_id": item.get("indexerId"),
        "protocol": protocol,
        "age_minutes": age_minutes,
        "age_label": _format_age_label(age_minutes),
        "raw": item,
    }


def _coerce_age_int(value):
    try:
        out = int(float(value))
    except Exception:
        return None
    return out if out >= 0 else None


def _parse_release_datetime(value):
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _extract_age_minutes(item):
    raw = item or {}
    for key in ("ageMinutes", "age_minutes"):
        age_value = _coerce_age_int(raw.get(key))
        if age_value is not None:
            return age_value
    for key in ("ageHours", "age_hours"):
        age_value = _coerce_age_int(raw.get(key))
        if age_value is not None:
            return age_value * 60
    age_value = _coerce_age_int(raw.get("age"))
    if age_value is not None:
        return age_value
    for key in ("publishDate", "publishedDate", "publishTime", "published", "pubDate"):
        dt = _parse_release_datetime(raw.get(key))
        if dt is None:
            continue
        return max(int((datetime.now(timezone.utc) - dt).total_seconds() // 60), 0)
    return None


def _format_age_label(age_minutes):
    if age_minutes is None:
        return ""
    if age_minutes < 60:
        return f"{int(age_minutes)} min"
    if age_minutes < 1440:
        hours = age_minutes / 60
        return f"{hours:.1f} h" if age_minutes % 60 else f"{int(hours)} h"
    if age_minutes < 10080:
        days = age_minutes / 1440
        return f"{days:.1f} d" if age_minutes % 1440 else f"{int(days)} d"
    weeks = age_minutes / 10080
    return f"{weeks:.1f} w" if age_minutes % 10080 else f"{int(weeks)} w"


def _normalize_protocol(item):
    raw_protocol = str(item.get("protocol") or item.get("protocolName") or "").strip().lower()
    if raw_protocol in ("torrent", "usenet"):
        return raw_protocol
    download_url = str(item.get("downloadUrl") or "").strip().lower()
    info_url = str(item.get("infoUrl") or "").strip().lower()
    combined = f"{download_url} {info_url}"
    if download_url.startswith("magnet:") or ".torrent" in combined:
        return "torrent"
    if ".nzb" in combined or "usenet" in combined or "newznab" in combined:
        return "usenet"
    return ""


def _normalize_text(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return text.strip()


def _has_version(text, version):
    if not version:
        return False
    version_str = str(version).lower()
    return version_str in text or f"v{version_str}" in text


def _extract_internal_version_token(text):
    raw = str(text or "")
    match = re.search(r"\[v(\d+)\]", raw, re.IGNORECASE)
    if not match:
        match = re.search(r"(?<![a-z0-9])v(\d+)(?!\.\d)", raw, re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def filter_results(results, min_seeders=0, min_age_minutes=0, required_terms=None, blacklist_terms=None):
    required_terms = [_normalize_text(t) for t in (required_terms or []) if t]
    blacklist_terms = [_normalize_text(t) for t in (blacklist_terms or []) if t]
    filtered = []
    for result in results:
        title = _normalize_text(result.get("title") or "")
        protocol = str(result.get("protocol") or "").strip().lower()
        if min_seeders and protocol != "usenet" and result.get("seeders", 0) < min_seeders:
            continue
        if min_age_minutes and protocol == "usenet":
            age_minutes = result.get("age_minutes")
            if age_minutes is None or int(age_minutes) < int(min_age_minutes):
                continue
        if required_terms and not all(term in title for term in required_terms):
            continue
        if blacklist_terms and any(term in title for term in blacklist_terms):
            continue
        filtered.append(result)
    return filtered


def _score_result(result, title_id=None, version=None):
    title = _normalize_text(result.get("title") or "")
    seeders = result.get("seeders", 0)
    protocol = str(result.get("protocol") or "").lower()

    has_title_id = bool(title_id and title_id.lower() in title)
    has_version = _has_version(title, version)
    has_update = "update" in title
    has_nsp = "nsp" in title or "nsz" in title

    score = 0
    if has_title_id:
        score += 50
    if has_version:
        score += 30
    if has_update:
        score += 10
    if has_nsp:
        score += 5
    if protocol == "usenet":
        score += 2

    seed_bonus = min(max(seeders, 0), 200)
    score += seed_bonus / 10
    return score


def pick_best_result(results, title_id=None, version=None, min_seeders=0, min_age_minutes=0, required_terms=None, blacklist_terms=None, allowed_protocols=None, require_exact_version=False):
    filtered = filter_results(
        results,
        min_seeders=min_seeders,
        min_age_minutes=min_age_minutes,
        required_terms=required_terms,
        blacklist_terms=blacklist_terms,
    )
    allowed = {str(item or "").strip().lower() for item in (allowed_protocols or []) if str(item or "").strip()}
    if allowed:
        filtered = [item for item in filtered if str(item.get("protocol") or "").strip().lower() in allowed]
    if require_exact_version and version is not None:
        expected_version = int(version)
        filtered = [
            item for item in filtered
            if _extract_internal_version_token(item.get("title")) == expected_version
        ]
    if not filtered:
        return None
    scored = [
        (result, _score_result(result, title_id=title_id, version=version))
        for result in filtered
    ]
    scored.sort(
        key=lambda item: (
            item[1],
            item[0].get("seeders", 0),
            -item[0].get("size", 0),
        ),
        reverse=True,
    )
    best = scored[0][0]
    logger.info("Selected prowlarr result: %s", best.get("title"))
    return best
