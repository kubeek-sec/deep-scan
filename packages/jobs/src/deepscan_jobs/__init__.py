"""deepscan-jobs - shared, Postgres-backed scan-job store and runner.

One queue and one schema reused by the API, the MCP server and kruncher. Jobs
carry an ``origin`` (``adhoc`` for API/MCP submissions, ``discovery`` for
kruncher's connector-driven scans); workers claim only the origins they can run.

    from deepscan_jobs import db, store, worker, uploads
    db.init_schema()
"""

from __future__ import annotations

from . import config, db, materialize, ramfs, store, uploads, worker
from .models import (
    ADHOC_TARGET_TYPES,
    OPEN_STATUSES,
    TERMINAL_STATUSES,
    JobOrigin,
    JobStatus,
)

__version__ = "0.1.0"

__all__ = [
    "config",
    "db",
    "materialize",
    "ramfs",
    "store",
    "uploads",
    "worker",
    "JobStatus",
    "JobOrigin",
    "ADHOC_TARGET_TYPES",
    "OPEN_STATUSES",
    "TERMINAL_STATUSES",
    "__version__",
]
