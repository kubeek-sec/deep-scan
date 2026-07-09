"""Postgres access: a lazily-built connection pool, schema bootstrap and the
advisory-lock helper used for scheduler leader election.

The whole design leans on Postgres for concurrency control:

* Workers claim jobs with ``SELECT ... FOR UPDATE SKIP LOCKED`` (see store),
  so N workers share one queue with no external broker.
* The scheduler wraps its tick in a session-level advisory lock, so running
  several scheduler replicas is safe - only the lock holder does work.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator
from importlib.resources import files
from typing import Any

import psycopg
from psycopg_pool import ConnectionPool

from . import config

# Arbitrary but fixed key so every replica contends for the same lock.
SCHEDULER_LOCK_KEY = 0x6465_6570  # "deep"

_pool: ConnectionPool | None = None
_pool_lock = threading.Lock()


def schema_sql() -> str:
    """Read the packaged canonical schema."""
    return (files("deepscan_jobs") / "schema.sql").read_text(encoding="utf-8")


def pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ConnectionPool(
                    conninfo=config.database_dsn(),
                    min_size=1,
                    max_size=config.pool_max_size(),
                    kwargs={"autocommit": False, "row_factory": psycopg.rows.dict_row},
                    open=True,
                )
    return _pool


@contextlib.contextmanager
def connection() -> Iterator[psycopg.Connection]:
    """A pooled connection; commits on clean exit, rolls back on exception."""
    with pool().connection() as conn:
        yield conn


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


def init_schema() -> None:
    """Apply the (idempotent) schema. Safe to run repeatedly."""
    ddl = schema_sql()
    with connection() as conn:
        conn.execute(ddl)
        conn.commit()


def ping() -> bool:
    with connection() as conn:
        conn.execute("SELECT 1")
    return True


@contextlib.contextmanager
def advisory_lock(conn: psycopg.Connection, key: int = SCHEDULER_LOCK_KEY) -> Iterator[bool]:
    """Try to take a session advisory lock; yield whether it was acquired.

    Non-blocking: a second scheduler simply gets ``False`` and skips its tick.
    """
    row = conn.execute("SELECT pg_try_advisory_lock(%s) AS locked", (key,)).fetchone()
    acquired = bool(row and row["locked"])
    try:
        yield acquired
    finally:
        if acquired:
            conn.execute("SELECT pg_advisory_unlock(%s)", (key,))
            conn.commit()


def fetchall(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with connection() as conn:
        return conn.execute(query, params).fetchall()


def fetchone(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with connection() as conn:
        return conn.execute(query, params).fetchone()


def execute(query: str, params: tuple[Any, ...] = ()) -> None:
    with connection() as conn:
        conn.execute(query, params)
        conn.commit()
