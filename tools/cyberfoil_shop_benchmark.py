#!/usr/bin/env python3
"""Simulate a Cyberfoil client connection and measure shop load time."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

import requests
from requests.auth import HTTPBasicAuth


@dataclass
class HttpSample:
    status_code: int
    duration_ms: float
    size_bytes: int
    content_type: str


@dataclass
class RunSample:
    run: int
    root: HttpSample
    sections: HttpSample
    total_ms: float
    sections_count: int
    items_count: int
    root_encrypted: bool


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure Cyberfoil-style shop loading by requesting / and /api/shop/sections."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8465", help="AeroFoil base URL.")
    parser.add_argument("--username", default="", help="HTTP Basic auth username (required for private shop).")
    parser.add_argument("--password", default="", help="HTTP Basic auth password.")
    parser.add_argument("--runs", type=int, default=5, help="Measured runs.")
    parser.add_argument("--warmup", type=int, default=1, help="Warmup runs (excluded from summary).")
    parser.add_argument("--limit", type=int, default=50, help="Query limit for /api/shop/sections.")
    parser.add_argument("--timeout", type=float, default=30.0, help="Request timeout in seconds.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--forwarded-https", action="store_true", help="Send X-Forwarded-Proto: https.")
    parser.add_argument(
        "--host-header",
        default="",
        help="Optional Host header override for strict shop host verification.",
    )
    parser.add_argument("--fresh-session-per-run", action="store_true", help="Do not reuse HTTP session between runs.")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output machine-readable JSON.")

    # Tinfoil/Cyberfoil marker headers expected by AeroFoil.
    parser.add_argument("--user-agent", default="Cyberfoil/1.0 (benchmark)", help="User-Agent header value.")
    parser.add_argument("--theme", default="Dark", help="Theme header value.")
    parser.add_argument("--uid", default=f"bench-{uuid.uuid4().hex[:16]}", help="Uid header value.")
    parser.add_argument("--version", default="17.0", help="Version header value.")
    parser.add_argument("--revision", default="0", help="Revision header value.")
    parser.add_argument("--language", default="en", help="Language header value.")
    parser.add_argument("--hauth", default="benchmark-hauth", help="Hauth header value.")
    parser.add_argument("--uauth", default="benchmark-uauth", help="Uauth header value.")

    args = parser.parse_args()

    if not args.base_url.startswith(("http://", "https://")):
        parser.error("--base-url must start with http:// or https://")
    if args.runs < 1:
        parser.error("--runs must be >= 1")
    if args.warmup < 0:
        parser.error("--warmup must be >= 0")
    if args.limit < 1:
        parser.error("--limit must be >= 1")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    if bool(args.username) != bool(args.password):
        parser.error("--username and --password must be provided together")

    args.base_url = args.base_url.rstrip("/")
    return args


def _build_headers(args: argparse.Namespace) -> dict[str, str]:
    headers = {
        "User-Agent": args.user_agent,
        "Theme": args.theme,
        "Uid": args.uid,
        "Version": args.version,
        "Revision": args.revision,
        "Language": args.language,
        "Hauth": args.hauth,
        "Uauth": args.uauth,
        "Accept": "*/*",
    }
    if args.forwarded_https:
        headers["X-Forwarded-Proto"] = "https"
    if args.host_header:
        headers["Host"] = args.host_header
    return headers


def _timed_get(
    session: requests.Session,
    url: str,
    headers: dict[str, str],
    timeout: float,
    verify_tls: bool,
    auth: HTTPBasicAuth | None,
    params: dict[str, Any] | None = None,
) -> tuple[requests.Response, HttpSample]:
    start = time.perf_counter()
    response = session.get(url, headers=headers, params=params, timeout=timeout, verify=verify_tls, auth=auth)
    duration_ms = (time.perf_counter() - start) * 1000.0
    sample = HttpSample(
        status_code=response.status_code,
        duration_ms=duration_ms,
        size_bytes=len(response.content or b""),
        content_type=response.headers.get("Content-Type", ""),
    )
    return response, sample


def _assert_ok(label: str, response: requests.Response) -> None:
    if 200 <= response.status_code < 300:
        return
    body = ""
    try:
        body = (response.text or "").strip().replace("\n", " ")
    except Exception:
        body = "<unavailable>"
    if len(body) > 300:
        body = body[:300] + "..."
    raise RuntimeError(f"{label} failed with HTTP {response.status_code}: {body}")


def _extract_sections_info(response: requests.Response) -> tuple[int, int]:
    try:
        payload = response.json()
    except ValueError:
        return 0, 0
    sections = payload.get("sections") if isinstance(payload, dict) else None
    if not isinstance(sections, list):
        return 0, 0

    sections_count = 0
    items_count = 0
    for section in sections:
        if not isinstance(section, dict):
            continue
        sections_count += 1
        items = section.get("items")
        if isinstance(items, list):
            items_count += len(items)
    return sections_count, items_count


def _assert_not_error_payload(label: str, response: requests.Response) -> None:
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "application/json" not in content_type:
        return
    try:
        payload = response.json()
    except ValueError:
        return
    if isinstance(payload, dict) and payload.get("error"):
        raise RuntimeError(f"{label} returned error payload: {payload.get('error')}")


def _assert_sections_payload(response: requests.Response) -> None:
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "application/json" not in content_type:
        raise RuntimeError("GET /api/shop/sections did not return JSON.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("GET /api/shop/sections returned invalid JSON.") from exc
    if isinstance(payload, dict) and payload.get("error"):
        raise RuntimeError(f"GET /api/shop/sections returned error payload: {payload.get('error')}")
    sections = payload.get("sections") if isinstance(payload, dict) else None
    if not isinstance(sections, list):
        raise RuntimeError("GET /api/shop/sections response missing 'sections' list.")


def _run_once(
    session: requests.Session,
    args: argparse.Namespace,
    headers: dict[str, str],
    auth: HTTPBasicAuth | None,
) -> RunSample:
    total_start = time.perf_counter()

    root_response, root_sample = _timed_get(
        session=session,
        url=f"{args.base_url}/",
        headers=headers,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        auth=auth,
    )
    _assert_ok("GET /", root_response)
    _assert_not_error_payload("GET /", root_response)
    root_encrypted = "application/octet-stream" in root_sample.content_type.lower()

    sections_response, sections_sample = _timed_get(
        session=session,
        url=f"{args.base_url}/api/shop/sections",
        headers=headers,
        params={"limit": str(args.limit)},
        timeout=args.timeout,
        verify_tls=not args.insecure,
        auth=auth,
    )
    _assert_ok("GET /api/shop/sections", sections_response)
    _assert_sections_payload(sections_response)
    sections_count, items_count = _extract_sections_info(sections_response)

    total_ms = (time.perf_counter() - total_start) * 1000.0
    return RunSample(
        run=0,
        root=root_sample,
        sections=sections_sample,
        total_ms=total_ms,
        sections_count=sections_count,
        items_count=items_count,
        root_encrypted=root_encrypted,
    )


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (percentile / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] + (ordered[high] - ordered[low]) * weight


def _build_summary(runs: list[RunSample]) -> dict[str, dict[str, float]]:
    totals = [item.total_ms for item in runs]
    roots = [item.root.duration_ms for item in runs]
    sections = [item.sections.duration_ms for item in runs]

    def _stats(values: list[float]) -> dict[str, float]:
        return {
            "min_ms": min(values),
            "mean_ms": statistics.fmean(values),
            "p50_ms": statistics.median(values),
            "p95_ms": _percentile(values, 95.0),
            "max_ms": max(values),
        }

    return {
        "total": _stats(totals),
        "root": _stats(roots),
        "sections": _stats(sections),
    }


def _print_text(args: argparse.Namespace, runs: list[RunSample], summary: dict[str, dict[str, float]]) -> None:
    print(f"Target: {args.base_url}")
    print(f"Measured runs: {args.runs} (warmup: {args.warmup})")
    print(f"Sections limit: {args.limit}")
    print(f"TLS verify: {not args.insecure}")
    print("")

    for run in runs:
        root_kind = "encrypted" if run.root_encrypted else "json"
        print(
            f"Run {run.run:>2}: "
            f"total={run.total_ms:8.2f} ms | "
            f"/={run.root.duration_ms:8.2f} ms ({run.root.size_bytes} B, {root_kind}) | "
            f"/api/shop/sections={run.sections.duration_ms:8.2f} ms "
            f"({run.sections_count} sections, {run.items_count} items)"
        )

    print("")
    print("Summary:")
    for key in ("total", "root", "sections"):
        stats = summary[key]
        print(
            f"  {key:8s} min={stats['min_ms']:.2f} ms  "
            f"mean={stats['mean_ms']:.2f} ms  "
            f"p50={stats['p50_ms']:.2f} ms  "
            f"p95={stats['p95_ms']:.2f} ms  "
            f"max={stats['max_ms']:.2f} ms"
        )


def main() -> int:
    args = _parse_args()
    headers = _build_headers(args)
    auth = HTTPBasicAuth(args.username, args.password) if args.username else None

    runs: list[RunSample] = []
    shared_session = requests.Session() if not args.fresh_session_per_run else None

    try:
        total_iterations = args.warmup + args.runs
        for iteration in range(1, total_iterations + 1):
            session = shared_session or requests.Session()
            try:
                sample = _run_once(session=session, args=args, headers=headers, auth=auth)
            finally:
                if args.fresh_session_per_run:
                    session.close()

            if iteration <= args.warmup:
                if not args.json_output:
                    print(
                        f"Warmup {iteration}/{args.warmup}: "
                        f"total={sample.total_ms:.2f} ms "
                        f"root={sample.root.duration_ms:.2f} ms "
                        f"sections={sample.sections.duration_ms:.2f} ms"
                    )
                continue

            sample.run = iteration - args.warmup
            runs.append(sample)
            if not args.json_output:
                print(f"Completed run {sample.run}/{args.runs}")
    finally:
        if shared_session is not None:
            shared_session.close()

    summary = _build_summary(runs)
    if args.json_output:
        output = {
            "target": args.base_url,
            "runs": [asdict(item) for item in runs],
            "summary": summary,
            "config": {
                "runs": args.runs,
                "warmup": args.warmup,
                "limit": args.limit,
                "timeout": args.timeout,
                "tls_verify": not args.insecure,
                "fresh_session_per_run": args.fresh_session_per_run,
            },
        }
        print(json.dumps(output, indent=2))
        return 0

    print("")
    _print_text(args, runs, summary)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.RequestException as exc:
        print(f"Request error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)

