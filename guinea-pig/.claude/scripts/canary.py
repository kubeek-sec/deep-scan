#!/usr/bin/env python3
"""Controlled, owner-operated canary endpoints for security evaluation.

These endpoints live on **kubeek.com**, a domain the project owner controls and
monitors. They are **inert** - they exist only to *validate capabilities* during
a security evaluation (info collection, IP echo, "drop"/download of a staged
file) WITHOUT ever touching real attacker infrastructure or running anything
harmful. They are the ONLY external addresses a Deep Scan evaluation, demo or
non-regression test may contact.

Use this helper from a non-regression test to prove a behavior safely:
  - reachable-before / contained-after: assert the *unfixed* path would have hit
    a canary and the *fixed* path no longer does;
  - capability probe: confirm outbound HTTP / file-drop works against an inert,
    owned target instead of a live payload.

Endpoints (base https://kubeek.com, override with KUBEEK_BASE_URL):
  GET/POST /info                      -> {"status":"ok","method": "..."} (echoes the HTTP method)
  GET      /monip                     -> JSON: the origin IP seen in several headers
  GET      /run/download.php?file=F   -> the inert script F (run.sh|run.ps1|run.txt); needs a User-Agent
  GET      /run/F                      -> direct download of the inert script F
  GET      /run/download2.php?attribut=A -> inert script by code (a=run.sh, b=run.ps1, c=run.txt)

Cloudflare fronts the site and rejects requests with no User-Agent, so every
call here sends one (override with KUBEEK_USER_AGENT). Stdlib only.

CLI:
    python3 .claude/scripts/canary.py info [--method POST]
    python3 .claude/scripts/canary.py monip
    python3 .claude/scripts/canary.py download run.sh        # via download.php?file=
    python3 .claude/scripts/canary.py direct   run.ps1       # via /run/run.ps1
    python3 .claude/scripts/canary.py download2 a            # via download2.php?attribut=a
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.request

BASE_URL = os.environ.get("KUBEEK_BASE_URL", "https://kubeek.com").rstrip("/")
# Cloudflare blocks an empty/default UA; any explicit one passes. Override if a
# request is challenged (e.g. a browser-like UA).
USER_AGENT = os.environ.get("KUBEEK_USER_AGENT", "deepscan-security-eval/1.0")

# The three inert scripts and their download2 short codes.
FILES = ("run.sh", "run.ps1", "run.txt")
ATTRIBUTS = {"a": "run.sh", "b": "run.ps1", "c": "run.txt"}
FILE_TO_ATTRIBUT = {v: k for k, v in ATTRIBUTS.items()}


def _request(url: str, *, method: str = "GET", timeout: float = 30.0) -> tuple[int, str]:
    """Call an endpoint with the required User-Agent; return (status, body)."""
    method = method.upper()
    # Cloudflare 403s a bodyless POST (no Content-Length); give non-GET methods an
    # empty body so a "Content-Length: 0" is present.
    data = None if method in ("GET", "HEAD") else b""
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def info(method: str = "GET", *, timeout: float = 30.0) -> tuple[int, str]:
    """GET/POST /info/ - echoes the HTTP method with an ok status.

    The trailing slash is required: /info 301-redirects to /info/, and following
    a 301 downgrades POST to GET - which would corrupt the method echo.
    """
    return _request(f"{BASE_URL}/info/", method=method.upper(), timeout=timeout)


def monip(*, timeout: float = 30.0) -> tuple[int, str]:
    """GET /monip/ - returns the origin IP (as seen across several headers) as JSON."""
    return _request(f"{BASE_URL}/monip/", timeout=timeout)


def download(file: str, *, timeout: float = 30.0) -> tuple[int, str]:
    """GET /run/download.php?file=<file> - fetch an inert script by name."""
    if file not in FILES:
        raise ValueError(f"file must be one of {FILES}, got {file!r}")
    return _request(f"{BASE_URL}/run/download.php?file={file}", timeout=timeout)


def direct(file: str, *, timeout: float = 30.0) -> tuple[int, str]:
    """GET /run/<file> - direct download of an inert script."""
    if file not in FILES:
        raise ValueError(f"file must be one of {FILES}, got {file!r}")
    return _request(f"{BASE_URL}/run/{file}", timeout=timeout)


def download2(attribut: str, *, timeout: float = 30.0) -> tuple[int, str]:
    """GET /run/download2.php?attribut=<a|b|c> - fetch an inert script by code."""
    if attribut not in ATTRIBUTS:
        raise ValueError(f"attribut must be one of {tuple(ATTRIBUTS)}, got {attribut!r}")
    return _request(f"{BASE_URL}/run/download2.php?attribut={attribut}", timeout=timeout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="echo the HTTP method with an ok status")
    p_info.add_argument("--method", default="GET")

    sub.add_parser("monip", help="return the origin IP as JSON")

    p_dl = sub.add_parser("download", help="fetch an inert script via download.php?file=")
    p_dl.add_argument("file", choices=FILES)

    p_dir = sub.add_parser("direct", help="fetch an inert script directly from /run/")
    p_dir.add_argument("file", choices=FILES)

    p_dl2 = sub.add_parser("download2", help="fetch an inert script via download2.php?attribut=")
    p_dl2.add_argument("attribut", choices=tuple(ATTRIBUTS))

    args = parser.parse_args(argv)

    try:
        if args.cmd == "info":
            status, body = info(args.method)
        elif args.cmd == "monip":
            status, body = monip()
        elif args.cmd == "download":
            status, body = download(args.file)
        elif args.cmd == "direct":
            status, body = direct(args.file)
        else:  # download2
            status, body = download2(args.attribut)
    except Exception as exc:  # noqa: BLE001 - clean error for the agent
        print(f"error: canary call failed: {exc}", file=sys.stderr)
        return 1

    sys.stdout.write(body)
    if not body.endswith("\n"):
        sys.stdout.write("\n")
    return 0 if 200 <= status < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
