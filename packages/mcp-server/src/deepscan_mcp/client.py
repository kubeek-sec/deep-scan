"""Client-side helper for the streamable-http transport.

Over http the server may be remote, so the project files have to be sent. This
zips a project directory (skipping VCS/venv/build noise) and POSTs it to the MCP
server's ``/upload`` endpoint, returning the ``upload_id`` to hand to a scan tool
(``static_scan(upload_id=...)`` etc.).

    from deepscan_mcp.client import upload_project
    upload_id = upload_project("./my-project", base_url="http://host:8000")
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import httpx

# Directories never worth shipping for a scan.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".tox", ".nox", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".idea", ".gradle", "target",
}


def build_zip(project_dir: str | Path) -> bytes:
    """Zip ``project_dir`` into an in-memory archive, skipping common noise."""
    root = Path(project_dir).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(root)
            if _SKIP_DIRS & set(rel.parts):
                continue
            zf.write(path, rel.as_posix())
    return buf.getvalue()


def upload_project(
    project_dir: str | Path,
    base_url: str = "http://127.0.0.1:8000",
    *,
    timeout: float = 120.0,
) -> str:
    """Zip ``project_dir`` and upload it to the MCP server; return the upload_id."""
    data = build_zip(project_dir)
    url = base_url.rstrip("/") + "/upload"
    resp = httpx.post(
        url,
        params={"filename": Path(project_dir).expanduser().resolve().name + ".zip"},
        content=data,
        headers={"content-type": "application/zip"},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["upload_id"]


__all__ = ["build_zip", "upload_project"]
