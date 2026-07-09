"""RAM-backed staging for scan execution.

The retained analyzed source lives on the shared ``/data`` volume; copying it
into a tmpfs (default ``/dev/shm``, see :func:`deepscan_jobs.config.scan_ramfs_dir`)
before scanning makes the scanners' heavy random reads hit RAM instead of disk.
The retained copy is the source of truth and is never touched here - only the
transient RAM copy is created and removed.

The RAM copy is **full fidelity - nothing is excluded** (``.git`` history,
CI/pipeline configs, vendored dependencies, build artifacts and all). Some
scanners walk the git history or inspect build/pipeline files, so everything
received must be present and scanned.

Best-effort by design: if RAM staging is disabled, the scratch is unavailable,
or the copy fails (e.g. the tmpfs is too small), the scan simply runs over the
retained copy in place. Staging must never make a scan fail.
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

from . import config

log = logging.getLogger("deepscan.jobs.ramfs")

# Skip RAM staging when the scratch has less than this free - copying would
# likely fail with ENOSPC anyway. A cheap sanity gate; the copy is still guarded.
_MIN_FREE_BYTES = 64 * 1024 * 1024


@contextlib.contextmanager
def staged_for_scan(source_path: str | Path) -> Iterator[str]:
    """Yield a path to scan.

    A RAM-backed copy of ``source_path`` when staging is enabled and feasible,
    otherwise ``source_path`` itself. Any RAM copy created here is removed on
    exit, including when the scan raises.
    """
    original = str(source_path)
    src = Path(original)
    ram_root = config.scan_ramfs_dir() if config.scan_ramfs_enabled() else None
    if ram_root is None or not src.is_dir():
        yield original
        return

    try:
        if shutil.disk_usage(ram_root).free < _MIN_FREE_BYTES:
            log.warning("RAM scratch %s is low on free space - scanning in place", ram_root)
            yield original
            return
    except OSError:
        yield original
        return

    dest = ram_root / "deepscan-scan" / uuid.uuid4().hex
    try:
        # Full-fidelity copy: nothing excluded so scanners see the complete tree
        # (git history, pipelines, vendored deps). Symlinks are preserved, not
        # dereferenced, so broken/relative links never abort the copy.
        shutil.copytree(src, dest, symlinks=True)
    except (OSError, shutil.Error) as exc:  # tmpfs full, perms - fall back to disk
        log.warning("RAM staging copy failed (%s) - scanning in place", exc)
        shutil.rmtree(dest, ignore_errors=True)
        yield original
        return

    log.info("scanning RAM copy at %s (retained source: %s)", dest, original)
    try:
        yield str(dest)
    finally:
        shutil.rmtree(dest, ignore_errors=True)
