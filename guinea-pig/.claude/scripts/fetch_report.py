#!/usr/bin/env python3
"""Fetch a Deep Scan report by job id or upload_id; optionally wait for it.

Mirror of fetch_report.sh / .ps1 (same CLI). Accepts a Job #N or an upload_id, and
can poll until the job is done - so it doubles as the RECOVERY path after the MCP
call drops with `MCP server "deepscan" session expired`: the scan keeps running
server-side, so never re-scan, just fetch it here (add --wait if it may still run).

    python3 fetch_report.py N                    # JSON for Job #N to stdout
    python3 fetch_report.py N --format md         # markdown
    python3 fetch_report.py <upload_id>           # newest job for that upload
    python3 fetch_report.py <upload_id> --wait    # wait until done, then fetch
    python3 fetch_report.py N --wait --interval 15 --timeout 3600

Stdlib only. API base defaults to http://127.0.0.1:8800 (override with --base-url
or DEEPSCAN_API_URL).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request


def _get(url: str, timeout: int = 15) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read()


def _scans(base: str) -> list:
    return json.loads(_get(f"{base}/api/scans"))


def _resolve_job(base: str, ident: str) -> int | None:
    if ident.isdigit():
        return int(ident)
    matches = [s for s in _scans(base) if ident in (s.get("target") or "")]
    return max(matches, key=lambda s: s["id"])["id"] if matches else None


def _wait_for(base: str, job: int, interval: int, timeout: int) -> None:
    elapsed = 0
    while True:
        status = next((s["status"] for s in _scans(base) if s["id"] == job), "unknown")
        if status == "done":
            print(f"job #{job} done", file=sys.stderr)
            return
        if status in ("failed", "error"):
            print(f"job #{job} FAILED", file=sys.stderr)
            sys.exit(1)
        print(f"  … #{job} {status} [{elapsed}s]", file=sys.stderr)
        if elapsed >= timeout:
            print(f"error: timeout after {timeout}s (job still {status})", file=sys.stderr)
            sys.exit(3)
        time.sleep(interval)
        elapsed += interval


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch a Deep Scan report by job id or upload_id.")
    parser.add_argument("id", help="Job #N, or an upload_id to resolve to its newest job")
    parser.add_argument("--format", default="json", choices=["json", "md", "html", "sarif", "junit"])
    parser.add_argument("--wait", action="store_true", help="poll until the job is done, then fetch")
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("DEEPSCAN_API_URL", "http://127.0.0.1:8800"),
        help="Deep Scan API base URL (default: http://127.0.0.1:8800)",
    )
    args = parser.parse_args(argv)
    base = args.base_url.rstrip("/")

    try:
        job = _resolve_job(base, args.id)
    except Exception as exc:  # noqa: BLE001 - clean error for the agent
        print(f"error: could not query {base}/api/scans: {exc}", file=sys.stderr)
        return 1
    if job is None:
        print(f"error: no job found for upload_id '{args.id}'", file=sys.stderr)
        return 1
    if not args.id.isdigit():
        print(f"resolved upload_id '{args.id}' -> job #{job}", file=sys.stderr)

    if args.wait:
        _wait_for(base, job, args.interval, args.timeout)

    url = f"{base}/api/scans/{job}/report?format={args.format}"
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:
            sys.stdout.write(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not fetch {url}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
