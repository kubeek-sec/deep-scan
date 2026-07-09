"""Kruncher configuration, read from the environment (``.env`` as fallback).

Database / queue settings (DSN, pool size, lease, retry backoff, worker id) now
live in the shared :mod:`deepscan_jobs.config` and are re-exported here so
``config.database_dsn()`` etc. keep working. Kruncher-only knobs (discovery /
worker cadence and the materialization scratch dir) stay below.
"""

from __future__ import annotations

from pathlib import Path

from deepscan_core import config as _core
from deepscan_jobs.config import (  # re-exported shared queue settings
    RETRY_BACKOFF_SECONDS,
    database_dsn,
    lease_seconds,
    max_attempts,
    pool_max_size,
    worker_id,
)

__all__ = [
    "RETRY_BACKOFF_SECONDS",
    "database_dsn",
    "lease_seconds",
    "max_attempts",
    "pool_max_size",
    "worker_id",
    "work_dir",
    "poll_interval_seconds",
    "scheduler_interval_seconds",
    "allow_private_targets",
    "allow_local_paths",
]


def allow_private_targets() -> bool:
    """Whether ad-hoc (manual) scan URLs may point at loopback/private hosts.

    The worker fleet is the trusted executor for manual API/MCP scans (which the
    submitting surface already validated), so this defaults to ``true``; set
    ``DEEPSCAN_ALLOW_PRIVATE_TARGETS=false`` to forbid private targets here too.
    """
    raw = _core.get("DEEPSCAN_ALLOW_PRIVATE_TARGETS")
    return (raw or "").strip().lower() != "false"


def allow_local_paths() -> bool:
    """Whether ad-hoc ``path`` targets on the worker filesystem are accepted.

    Only meaningful when the path is reachable from the worker (e.g. a shared
    volume). Defaults to ``true``; set ``DEEPSCAN_ALLOW_LOCAL_PATHS=false`` to
    refuse server-side paths on the fleet.
    """
    raw = _core.get("DEEPSCAN_ALLOW_LOCAL_PATHS")
    return (raw or "").strip().lower() != "false"


def work_dir() -> Path:
    """Legacy worker-local scratch root (``DEEPSCAN_KRUNCHER_WORK_DIR``).

    No longer used to materialize discovery sources - those are now retained on
    the shared volume under ``deepscan_jobs.config.job_source_dir`` (e.g.
    ``sources/discovery/job-<id>``) so the API can serve them. Kept because the
    env var still drives ``TMPDIR`` /
    ``XDG_CACHE_HOME`` in the deployments (heavy scanner scratch); removing it
    would break those.
    """
    raw = _core.get("DEEPSCAN_KRUNCHER_WORK_DIR")
    base = Path(raw).expanduser() if raw else Path.home() / ".local" / "share" / "deepscan" / "kruncher"
    base.mkdir(parents=True, exist_ok=True)
    return base


def poll_interval_seconds(default: int = 5) -> int:
    return _int("DEEPSCAN_KRUNCHER_POLL_INTERVAL", default)


def scheduler_interval_seconds(default: int = 60) -> int:
    return _int("DEEPSCAN_KRUNCHER_SCHEDULER_INTERVAL", default)


def _int(key: str, default: int) -> int:
    raw = _core.get(key)
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return default
