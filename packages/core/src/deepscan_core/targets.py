"""Acquisition of remote scan targets: git repositories and zip archives.

Used by the REST API and CLI to materialize a target into a local directory
before a static scan. Both paths are defensive: git clones are shallow with
prompts disabled, zip extraction rejects traversal, symlinks and zip bombs.
"""

from __future__ import annotations

import os
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

_GIT_TIMEOUT = 300
_MAX_ZIP_ENTRIES = 50_000
_MAX_ZIP_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB uncompressed
_MAX_COMPRESSION_RATIO = 200


class TargetError(ValueError):
    pass


def clone_git(url: str, dest: Path) -> Path:
    """Shallow-clone an HTTPS git URL into ``dest`` (must not exist)."""
    url = (url or "").strip()
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise TargetError("Only http(s) git URLs are supported.")
    if not parts.hostname:
        raise TargetError("Git URL has no host.")
    if url.startswith("-"):
        raise TargetError("Git URL may not start with '-'.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"  # never hang on a credential prompt
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", "--", url, str(dest)],
        capture_output=True,
        text=True,
        timeout=_GIT_TIMEOUT,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise TargetError(f"git clone failed: {result.stderr.strip()[:500]}")
    return dest


def extract_zip(archive_path: Path, dest: Path) -> Path:
    """Safely extract a zip archive into ``dest``."""
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    try:
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            if len(entries) > _MAX_ZIP_ENTRIES:
                raise TargetError(f"Zip has too many entries (> {_MAX_ZIP_ENTRIES}).")
            total = sum(e.file_size for e in entries)
            if total > _MAX_ZIP_TOTAL_BYTES:
                raise TargetError("Zip uncompressed size exceeds the limit.")
            for entry in entries:
                if _is_symlink(entry):
                    continue  # never materialize symlinks from an archive
                if entry.compress_size:
                    ratio = entry.file_size / entry.compress_size
                    if ratio > _MAX_COMPRESSION_RATIO and entry.file_size > 1024 * 1024:
                        raise TargetError(
                            f"Suspicious compression ratio for {entry.filename!r}."
                        )
                target = (dest / entry.filename).resolve()
                if target != dest_resolved and dest_resolved not in target.parents:
                    raise TargetError(f"Zip entry escapes target dir: {entry.filename!r}")
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as src, open(target, "wb") as out:
                    while chunk := src.read(1024 * 1024):
                        out.write(chunk)
    except zipfile.BadZipFile as exc:
        raise TargetError(f"Invalid zip archive: {exc}") from exc
    return dest


def _is_symlink(entry: zipfile.ZipInfo) -> bool:
    return (entry.external_attr >> 16) & 0o170000 == 0o120000
