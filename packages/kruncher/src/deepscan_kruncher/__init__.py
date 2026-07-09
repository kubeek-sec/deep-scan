"""deepscan-kruncher - periodic, change-driven scanning of connector sources.

The kruncher is split into a cheap **scheduler** (discover scopes, probe for
changes, enqueue) and an expensive **worker** (claim, materialize, scan,
persist), sharing one Postgres-backed queue that needs no external broker.

    from deepscan_kruncher import db, store, scheduler, worker
    db.init_schema()
    worker.process_one()
"""

from __future__ import annotations

from . import config, connectors, db, discovery, scheduler, store, worker

__version__ = "0.1.0"

__all__ = [
    "config",
    "connectors",
    "db",
    "discovery",
    "scheduler",
    "store",
    "worker",
    "__version__",
]
