"""Disk retention for the shared data volume: retained analyzed **sources**
(cloned repos - usually the bulk), **reports** and zip **uploads**.

Prune oldest-first by any combination of:
  * age        - drop job dirs older than N days (report/source date);
  * size cap   - keep the whole store under G GiB;
  * free space - ensure at least F GiB free on the volume.

Non-terminal jobs (queued/running) are always protected, and only the
``reports/``, ``sources/`` and ``uploads/`` subtrees of the data dir are ever
touched (never arbitrary paths, never the buckets themselves)."""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config, store

_GIB = 1024 ** 3


@dataclass
class _Entry:
    path: Path
    kind: str          # reports | sources | uploads
    job_id: int | None
    mtime: float
    size: int


@dataclass
class PruneResult:
    scanned: int = 0
    protected: int = 0     # skipped because the job is still active
    deleted: int = 0
    freed_bytes: int = 0
    deleted_paths: list[str] = field(default_factory=list)
    dry_run: bool = False

    @property
    def freed_gib(self) -> float:
        return self.freed_bytes / _GIB


def _dir_size(p: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(p):
        for name in files:
            try:
                total += (Path(root) / name).lstat().st_size
            except OSError:
                pass
    return total


def _job_id_from(name: str) -> int | None:
    """``job-42`` -> 42; anything else (e.g. an upload id) -> None."""
    if name.startswith("job-"):
        try:
            return int(name[4:])
        except ValueError:
            return None
    return None


def _entry(d: Path, kind: str) -> _Entry:
    st = d.stat()
    return _Entry(d, kind, _job_id_from(d.name), st.st_mtime, _dir_size(d))


def _collect(base: Path, targets: tuple[str, ...]) -> list[_Entry]:
    """The prunable leaf dirs: reports/job-*, sources/<bucket>/job-*, uploads/*."""
    entries: list[_Entry] = []
    if "reports" in targets:
        for d in sorted((base / "reports").glob("job-*")):
            if d.is_dir():
                entries.append(_entry(d, "reports"))
    if "sources" in targets:
        for bucket in sorted((base / "sources").glob("*")):
            if bucket.is_dir():
                for d in sorted(bucket.glob("job-*")):
                    if d.is_dir():
                        entries.append(_entry(d, "sources"))
    if "uploads" in targets:
        for d in sorted((base / "uploads").glob("*")):
            if d.is_dir():
                entries.append(_entry(d, "uploads"))
    return entries


def prune(
    *,
    max_age_days: float | None = None,
    max_size_gb: float | None = None,
    min_free_gb: float | None = None,
    targets: tuple[str, ...] = ("reports", "sources", "uploads"),
    dry_run: bool = False,
    now: float | None = None,
) -> PruneResult:
    """Delete retained job dirs per the given criteria (oldest-first). At least
    one of ``max_age_days`` / ``max_size_gb`` / ``min_free_gb`` should be set;
    with none, nothing is deleted."""
    now = now if now is not None else time.time()
    base = config.data_dir()
    res = PruneResult(dry_run=dry_run)

    entries = _collect(base, targets)
    res.scanned = len(entries)
    active = store.active_job_ids()
    candidates = [e for e in entries if not (e.job_id is not None and e.job_id in active)]
    res.protected = len(entries) - len(candidates)
    candidates.sort(key=lambda e: e.mtime)  # oldest first

    marked: dict[Path, _Entry] = {}

    # 1) age
    if max_age_days is not None:
        cutoff = now - max_age_days * 86400
        for e in candidates:
            if e.mtime < cutoff:
                marked[e.path] = e

    # 2) size cap: evict oldest (unmarked) until the whole store is under the cap.
    #    Active dirs still count toward the total (they occupy real space).
    if max_size_gb is not None:
        total = sum(e.size for e in entries)
        cap = max_size_gb * _GIB
        total -= sum(e.size for e in marked.values())
        for e in candidates:
            if total <= cap:
                break
            if e.path not in marked:
                marked[e.path] = e
                total -= e.size

    # 3) free space: evict oldest (unmarked) until the estimated free space meets
    #    the target (deleting a dir frees ~its size).
    if min_free_gb is not None:
        free = shutil.disk_usage(base).free + sum(e.size for e in marked.values())
        want = min_free_gb * _GIB
        for e in candidates:
            if free >= want:
                break
            if e.path not in marked:
                marked[e.path] = e
                free += e.size

    for e in sorted(marked.values(), key=lambda x: x.mtime):
        res.deleted_paths.append(str(e.path))
        res.freed_bytes += e.size
        res.deleted += 1
        if not dry_run:
            shutil.rmtree(e.path, ignore_errors=True)
    return res
