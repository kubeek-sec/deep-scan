"""Postgres access for kruncher.

The connection pool, schema bootstrap and advisory-lock helper now live in the
shared :mod:`deepscan_jobs.db` (the schema is unified across the API, MCP server
and kruncher). This module re-exports them so existing ``from . import db``
call-sites keep working unchanged.
"""

from __future__ import annotations

from deepscan_jobs.db import (
    SCHEDULER_LOCK_KEY,
    advisory_lock,
    close_pool,
    connection,
    execute,
    fetchall,
    fetchone,
    init_schema,
    ping,
    pool,
    schema_sql,
)

__all__ = [
    "SCHEDULER_LOCK_KEY",
    "advisory_lock",
    "close_pool",
    "connection",
    "execute",
    "fetchall",
    "fetchone",
    "init_schema",
    "ping",
    "pool",
    "schema_sql",
]
