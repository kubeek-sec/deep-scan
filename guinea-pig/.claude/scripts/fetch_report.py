#!/usr/bin/env python3
"""Fetch a finished scan's report from the Deep Scan API by job id.

The MCP scan tools print "Job #N" in their output; pass N here to pull the
structured report (default JSON) so the grouping step has precise data:

    python3 .claude/scripts/fetch_report.py N                       # JSON to stdout
    python3 .claude/scripts/fetch_report.py N --format md           # markdown
    python3 .claude/scripts/fetch_report.py N --base-url http://127.0.0.1:8800

Stdlib only. The API base defaults to http://127.0.0.1:8800 (override with
--base-url or DEEPSCAN_API_URL).
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.request


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch a Deep Scan report by job id.")
    parser.add_argument("job_id", help="the job number the MCP tool printed (e.g. 42)")
    parser.add_argument(
        "--format", default="json", choices=["json", "md", "html", "sarif", "junit"]
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("DEEPSCAN_API_URL", "http://127.0.0.1:8800"),
        help="Deep Scan API base URL (default: http://127.0.0.1:8800)",
    )
    args = parser.parse_args(argv)

    url = f"{args.base_url.rstrip('/')}/api/scans/{args.job_id}/report?format={args.format}"
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            sys.stdout.write(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - clean error for the agent
        print(f"error: could not fetch {url}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
