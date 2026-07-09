"""Turn an ad-hoc job target into something ``run_scan`` accepts.

Factored out of the old ``deepscan_api.queue._materialize`` so the API, the MCP
server and any future front-end resolve url/git/path/zip identically, reusing
the safe acquisition helpers in ``deepscan_core``.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from deepscan_core.targets import TargetError, clone_git
from deepscan_core.validation import (
    ScanTargetError,
    resolve_scan_dir,
    validate_target_url,
)


async def materialize_adhoc(
    target_type: str,
    target: str,
    target_dir: Path,
    *,
    allow_private: bool = True,
    allow_local_paths: bool = True,
) -> str:
    """Return the ``scan_target`` (a directory or URL) for an ad-hoc job.

    The retrieved files are *retained* in ``target_dir`` (the per-job
    ``sources/<surface>/job-<id>`` store; the caller records its path on the job
    and never deletes it): ``git`` clones into it, ``zip`` copies the extracted
    upload into it (the raw ``uploads/<id>`` staging is kept too). ``path`` /
    ``url`` are used in place - nothing is retrieved.
    """
    if target_type == "url":
        return validate_target_url(target, allow_private=allow_private)
    if target_type == "git":
        await asyncio.to_thread(clone_git, target, target_dir)
        return str(target_dir)
    if target_type == "zip":
        # ``target`` is the dir a zip upload was already extracted into (uploads/
        # <id>). Copy it - in full - into the per-job sources store for posterity,
        # keeping the uploads/ staging for dezip + traceability.
        staged = Path(target)
        if not staged.is_dir():
            raise TargetError("Extracted zip target is missing on disk.")
        await asyncio.to_thread(
            shutil.copytree, staged, target_dir, symlinks=True, dirs_exist_ok=True
        )
        return str(target_dir)
    if target_type == "path":
        if not allow_local_paths:
            raise ScanTargetError("Local path targets are disabled.")
        return str(resolve_scan_dir(target))
    raise ValueError(f"Unknown target_type {target_type!r}.")
