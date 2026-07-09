"""Configuration for the shared job store, read from the environment.

Reuses ``deepscan_core.config.get`` so precedence matches the rest of the
monorepo: real environment variables win over a local ``.env``.

Env var names are generic (``DEEPSCAN_DB_*``, ``DEEPSCAN_DATA_DIR``,
``DEEPSCAN_LEASE_SECONDS`` …) with the legacy ``DEEPSCAN_KRUNCHER_*`` names kept
as fallbacks so existing kruncher deployments keep working.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

from deepscan_core import config as _core

# Default backoff schedule (seconds) indexed by the attempt that just failed.
RETRY_BACKOFF_SECONDS = (30, 120, 600)


def database_dsn() -> str:
    """Postgres connection string.

    ``DEEPSCAN_DB_DSN`` wins; otherwise assembled from discrete parts so the
    same image works with a URL secret or with split env vars from K8s.
    """
    dsn = _core.get("DEEPSCAN_DB_DSN")
    if dsn:
        return dsn
    host = _core.get("DEEPSCAN_DB_HOST") or "localhost"
    port = _core.get("DEEPSCAN_DB_PORT") or "5432"
    name = _core.get("DEEPSCAN_DB_NAME") or "deepscan"
    user = _core.get("DEEPSCAN_DB_USER") or "deepscan"
    password = _core.get("DEEPSCAN_DB_PASSWORD") or ""
    auth = f"{user}:{password}" if password else user
    return f"postgresql://{auth}@{host}:{port}/{name}"


def worker_id() -> str:
    """Stable-ish identity for a worker process (for ``locked_by``)."""
    explicit = _core.get("DEEPSCAN_WORKER_ID") or _core.get("DEEPSCAN_KRUNCHER_ID")
    if explicit:
        return explicit
    return f"{socket.gethostname()}:{os.getpid()}"


def data_dir() -> Path:
    """Shared directory holding ``sources/``, ``reports/`` and ``uploads/``.

    Must be the same volume across the API, MCP and kruncher processes so a
    report (or retained source) written by one is fetchable by the others.
    """
    raw = _core.get("DEEPSCAN_DATA_DIR") or _core.get("DEEPSCAN_API_DATA_DIR")
    base = Path(raw).expanduser().resolve() if raw else Path.home() / ".local" / "share" / "deepscan"
    base.mkdir(parents=True, exist_ok=True)
    return base


# --------------------------------------------------------------------------- #
# Retained analyzed-source storage.
#
# Every scan's retrieved files are kept on the shared volume under
# ``sources/<bucket>/job-<id>`` so they can be retrieved later (the path is
# recorded on the job). The bucket is the submitting *surface* for ad-hoc jobs
# (``api`` / ``mcp`` / ``cli``) and ``discovery`` for kruncher jobs - e.g.
# ``sources/api/job-42``. Zip uploads ALSO keep their raw ``uploads/<id>``
# staging dir (dezip + traceability); the job links it via ``upload_id``. Local
# ``path`` / ``url`` ad-hoc targets are referenced in place (nothing retrieved).
# Reports for every job live flat under ``reports/job-<id>``.
# --------------------------------------------------------------------------- #


def sources_dir() -> Path:
    """Root of the retained per-job analyzed-source store (on the shared volume)."""
    d = data_dir() / "sources"
    d.mkdir(parents=True, exist_ok=True)
    return d


def source_bucket(origin: str | None, surface: str | None) -> str:
    """Sub-directory of ``sources/`` for a job: its surface (api/mcp/cli) for
    ad-hoc jobs, ``discovery`` for kruncher (periodic) jobs."""
    if origin == "discovery":
        return "discovery"
    return surface or "adhoc"


def job_source_dir(job_id: int, *, origin: str | None = None, surface: str | None = None) -> Path:
    """Retained source dir for a job, e.g. ``sources/api/job-<id>``."""
    return sources_dir() / source_bucket(origin, surface) / f"job-{job_id}"


def job_report_dir(job_id: int) -> Path:
    """Where a job's report files live (flat, every origin): ``reports/job-<id>``."""
    return data_dir() / "reports" / f"job-{job_id}"


# --------------------------------------------------------------------------- #
# RAM-backed scan execution. Scanners run over a copy of the retained source in
# a tmpfs (default ``/dev/shm``) for faster I/O; the retained copy on ``/data``
# is the source of truth and survives a scan failure. Enabled by default, turned
# off with ``DEEPSCAN_SCAN_RAMFS=false`` (then the scan runs on the retained
# copy directly). In containers point ``DEEPSCAN_SCAN_RAMFS_DIR`` at a sized
# tmpfs mount - Docker's default ``/dev/shm`` is only 64 MiB.
# --------------------------------------------------------------------------- #

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


def scan_ramfs_enabled() -> bool:
    """Whether to copy the source into a RAM filesystem before scanning."""
    raw = (_core.get("DEEPSCAN_SCAN_RAMFS") or "").strip().lower()
    return raw not in _FALSE  # default on; only an explicit falsey value disables


def scan_ramfs_dir() -> Path | None:
    """The RAM-backed scratch root, or ``None`` when RAM staging is unavailable.

    ``DEEPSCAN_SCAN_RAMFS_DIR`` wins; otherwise ``/dev/shm`` when it exists and is
    writable. Returns ``None`` (caller scans in place) when neither is usable.
    """
    raw = _core.get("DEEPSCAN_SCAN_RAMFS_DIR")
    candidate = Path(raw).expanduser() if raw else Path("/dev/shm")
    if candidate.is_dir() and os.access(candidate, os.W_OK):
        return candidate
    return None


def pool_max_size(default: int = 4) -> int:
    return _int_any(("DEEPSCAN_DB_POOL", "DEEPSCAN_KRUNCHER_DB_POOL"), default)


def lease_seconds(default: int = 1800) -> int:
    """A running job whose heartbeat is older than this is considered dead."""
    return _int_any(("DEEPSCAN_LEASE_SECONDS", "DEEPSCAN_KRUNCHER_LEASE_SECONDS"), default)


def max_attempts(default: int = 3) -> int:
    return _int_any(("DEEPSCAN_MAX_ATTEMPTS", "DEEPSCAN_KRUNCHER_MAX_ATTEMPTS"), default)


def _int_any(keys: tuple[str, ...], default: int) -> int:
    for key in keys:
        raw = _core.get(key)
        if raw:
            try:
                return max(1, int(raw))
            except ValueError:
                pass
    return default
