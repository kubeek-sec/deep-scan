#!/usr/bin/env python3
"""Zip the project and upload it to the Deep Scan MCP server's ``/upload`` endpoint.

Step 1 of ``/security-eval``: over the streamable-http transport the project must
be sent to the (possibly remote) MCP server, which unzips it and scans it on the
shared jobs infrastructure. Prints the returned ``upload_id`` to **stdout** - pass
it to a scan tool, e.g. ``static_scan(upload_id=<id>)`` or
``scan_family(family, upload_id=<id>)``.

The MCP base URL is read from ``.mcp.json`` (the ``deepscan`` server's ``url``,
with a trailing ``/mcp`` stripped) unless ``--base-url`` is given. Stdlib only
(zipfile / urllib / json) so it runs in any project with nothing installed.

    python3 .claude/scripts/upload_to_mcp.py [TARGET_DIR]
    # → prints an upload_id; then call static_scan(upload_id=<id>)
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

# VCS / dependency / build dirs never worth uploading for a scan.
SKIP_DIRS = {
    ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".tox", ".nox", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".idea", "target",
}
MAX_BYTES = 200 * 1024 * 1024  # matches the server upload limit

# Exact project-relative files to leave OUT of the zip: the guinea-pig's own
# test-harness scaffolding (canary endpoints, /security-* commands, helper
# scripts) - tooling, not code under test. Matched by EXACT posix path relative
# to the zip root, NOT by dropping the whole .claude dir - so any real skills or
# commands a target project keeps under .claude are still uploaded and scanned.
# Add a path here when a new harness file lands under .claude.
SKIP_FILES = {
    ".claude/canary-endpoints.md",
    ".claude/settings.local.json",
    ".claude/commands/security.md",
    ".claude/commands/security-eval.md",
    ".claude/commands/security-patch.md",
    ".claude/scripts/README.md",
    ".claude/scripts/canary.py",
    ".claude/scripts/canary.sh",
    ".claude/scripts/canary.ps1",
    ".claude/scripts/fetch_report.py",
    ".claude/scripts/fetch_report.sh",
    ".claude/scripts/fetch_report.ps1",
    ".claude/scripts/upload_to_mcp.py",
    ".claude/scripts/upload_to_mcp.sh",
    ".claude/scripts/upload_to_mcp.ps1",
}


def find_mcp_url(config_path: str, server: str) -> tuple[str | None, str | None]:
    """(url, error) for the named MCP server in ``.mcp.json``."""
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"could not read {config_path}: {exc}"
    servers = data.get("mcpServers", {})
    entry = servers.get(server) or (next(iter(servers.values()), None) if servers else None)
    if not entry:
        return None, f"no MCP server {server!r} in {config_path}"
    url = entry.get("url")
    if not url:
        return None, (
            f"server {server!r} has no url (stdio transport?) - over stdio no upload "
            "is needed: scan by project_dir instead, or pass --base-url"
        )
    return url, None


def base_from_mcp_url(url: str) -> str:
    """The server base URL: the MCP url with a trailing ``/mcp`` removed."""
    base = url.rstrip("/")
    if base.endswith("/mcp"):
        base = base[: -len("/mcp")]
    return base


def build_zip(target: Path) -> bytes:
    buf = io.BytesIO()
    total = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(target.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(target)
            if SKIP_DIRS & set(rel.parts):
                continue
            if rel.as_posix() in SKIP_FILES:
                continue
            total += path.stat().st_size
            if total > MAX_BYTES:
                raise SystemExit(
                    "project exceeds the 200 MiB upload limit - remove build/vendor dirs"
                )
            zf.write(path, rel.as_posix())
    return buf.getvalue()


def upload(upload_url: str, data: bytes, filename: str) -> str:
    req = urllib.request.Request(
        f"{upload_url}?filename={urllib.parse.quote(filename)}",
        data=data,
        method="POST",
        headers={"Content-Type": "application/zip"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body["upload_id"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zip a project and upload it to the Deep Scan MCP server."
    )
    parser.add_argument("target", nargs="?", default=".", help="project dir to zip (default: cwd)")
    parser.add_argument("--mcp-config", default=".mcp.json", help="path to .mcp.json (default: ./.mcp.json)")
    parser.add_argument("--server", default="deepscan", help="MCP server name in .mcp.json")
    parser.add_argument("--base-url", help="override the server base URL (e.g. http://127.0.0.1:8000)")
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"error: not a directory: {target}", file=sys.stderr)
        return 2

    base = args.base_url
    if not base:
        url, err = find_mcp_url(args.mcp_config, args.server)
        if err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        base = base_from_mcp_url(url)
    upload_url = f"{base.rstrip('/')}/upload"

    print(f"zipping {target} …", file=sys.stderr)
    data = build_zip(target)
    print(f"uploading {len(data) / 1024 / 1024:.1f} MiB to {upload_url} …", file=sys.stderr)
    try:
        upload_id = upload(upload_url, data, f"{target.name}.zip")
    except Exception as exc:  # noqa: BLE001 - surface a clean error to the agent
        print(f"error: upload failed ({upload_url}): {exc}", file=sys.stderr)
        return 1
    print(upload_id)  # stdout: just the id, easy to capture
    print(f"ok - pass upload_id={upload_id} to static_scan / scan_family", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
