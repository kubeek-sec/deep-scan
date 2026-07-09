"""Data-access layer for scopes and sources (kruncher's discovery model).

The job-queue lifecycle (enqueue/claim/heartbeat/persist/fail/...) now lives in
the shared :mod:`deepscan_jobs.store` so the API, MCP server and kruncher share
one queue. Those functions are re-exported below.

The kruncher worker fleet now executes *both* queues - periodic
(``origin='discovery'``) and manual (``origin='adhoc'``, API/MCP) - so the
kruncher read surfaces (admin, CLI) default to showing both, with the ``origin``
filter available to look at one queue at a time.
"""

from __future__ import annotations

import json
from typing import Any

from deepscan_input_connector_base import DiscoveredSource

from deepscan_jobs import store as _jobs
from deepscan_jobs.models import OPEN_STATUSES, TERMINAL_STATUSES  # noqa: F401 (re-export)

from . import db
from .connectors import available


# --------------------------------------------------------------------------- #
# Scopes
# --------------------------------------------------------------------------- #


def upsert_scope(
    *,
    name: str,
    connector: str,
    scope_config: dict[str, Any],
    enabled: bool = True,
    refresh_interval_seconds: int = 3600,
    rescan_interval_seconds: int = 86400,
    families: list[str] | None = None,
) -> dict[str, Any]:
    """Create or update a scope by ``name`` (the natural key)."""
    if connector not in available():
        raise ValueError(
            f"Unknown connector {connector!r}. Available: {', '.join(available())}"
        )
    with db.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO scopes (name, connector, config, enabled,
                                refresh_interval_seconds, rescan_interval_seconds, families)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (name) DO UPDATE SET
                connector = EXCLUDED.connector,
                config = EXCLUDED.config,
                enabled = EXCLUDED.enabled,
                refresh_interval_seconds = EXCLUDED.refresh_interval_seconds,
                rescan_interval_seconds = EXCLUDED.rescan_interval_seconds,
                families = EXCLUDED.families,
                updated_at = now()
            RETURNING *
            """,
            (
                name,
                connector,
                json.dumps(scope_config),
                enabled,
                refresh_interval_seconds,
                rescan_interval_seconds,
                families or [],
            ),
        ).fetchone()
        conn.commit()
    return row


def list_scopes(enabled_only: bool = False) -> list[dict[str, Any]]:
    where = "WHERE enabled" if enabled_only else ""
    return db.fetchall(f"SELECT * FROM scopes {where} ORDER BY name")


def get_scope(scope_id: int) -> dict[str, Any] | None:
    return db.fetchone("SELECT * FROM scopes WHERE id = %s", (scope_id,))


def get_scope_by_name(name: str) -> dict[str, Any] | None:
    return db.fetchone("SELECT * FROM scopes WHERE name = %s", (name,))


def set_scope_enabled(scope_id: int, enabled: bool) -> None:
    db.execute(
        "UPDATE scopes SET enabled = %s, updated_at = now() WHERE id = %s",
        (enabled, scope_id),
    )


def update_scope(
    scope_id: int,
    *,
    name: str,
    connector: str,
    scope_config: dict[str, Any],
    enabled: bool,
    refresh_interval_seconds: int,
    rescan_interval_seconds: int,
    families: list[str] | None = None,
) -> dict[str, Any] | None:
    """Full update of a scope by id (rename allowed)."""
    if connector not in available():
        raise ValueError(
            f"Unknown connector {connector!r}. Available: {', '.join(available())}"
        )
    with db.connection() as conn:
        row = conn.execute(
            """
            UPDATE scopes SET
                name = %s, connector = %s, config = %s, enabled = %s,
                refresh_interval_seconds = %s, rescan_interval_seconds = %s,
                families = %s, updated_at = now()
            WHERE id = %s
            RETURNING *
            """,
            (
                name,
                connector,
                json.dumps(scope_config),
                enabled,
                refresh_interval_seconds,
                rescan_interval_seconds,
                families or [],
                scope_id,
            ),
        ).fetchone()
        conn.commit()
    return row


def delete_scope(scope_id: int) -> None:
    db.execute("DELETE FROM scopes WHERE id = %s", (scope_id,))


def scopes_due_for_discovery() -> list[dict[str, Any]]:
    return db.fetchall(
        """
        SELECT * FROM scopes
        WHERE enabled
          AND (last_discovered_at IS NULL
               OR last_discovered_at < now() - make_interval(secs => refresh_interval_seconds))
        ORDER BY last_discovered_at NULLS FIRST
        """
    )


def mark_scope_discovered(scope_id: int) -> None:
    db.execute(
        "UPDATE scopes SET last_discovered_at = now(), updated_at = now() WHERE id = %s",
        (scope_id,),
    )


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #


def upsert_source(scope_id: int, source: DiscoveredSource) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO sources (scope_id, external_id, kind, name, location,
                                 default_branch, metadata, active, last_seen_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, true, now())
            ON CONFLICT (scope_id, external_id) DO UPDATE SET
                kind = EXCLUDED.kind,
                name = EXCLUDED.name,
                location = EXCLUDED.location,
                default_branch = EXCLUDED.default_branch,
                metadata = EXCLUDED.metadata,
                active = true,
                last_seen_at = now()
            RETURNING *
            """,
            (
                scope_id,
                source.external_id,
                source.kind,
                source.name,
                source.location,
                source.default_branch,
                json.dumps(source.metadata),
            ),
        ).fetchone()
        conn.commit()
    return row


def deactivate_missing_sources(scope_id: int, seen_external_ids: list[str]) -> int:
    """Mark sources no longer reported by discovery as inactive (not deleted)."""
    with db.connection() as conn:
        cur = conn.execute(
            """
            UPDATE sources SET active = false
            WHERE scope_id = %s AND active = true
              AND NOT (external_id = ANY(%s))
            """,
            (scope_id, seen_external_ids or [""]),
        )
        conn.commit()
        return cur.rowcount


def list_sources(
    scope_id: int | None = None, active_only: bool = True, limit: int = 1000
) -> list[dict[str, Any]]:
    clauses, params = [], []
    if scope_id is not None:
        clauses.append("scope_id = %s")
        params.append(scope_id)
    if active_only:
        clauses.append("active")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    return db.fetchall(
        f"SELECT * FROM sources {where} ORDER BY name LIMIT %s", tuple(params)
    )


def get_source(source_id: int) -> dict[str, Any] | None:
    return db.fetchone("SELECT * FROM sources WHERE id = %s", (source_id,))


def update_source(
    source_id: int,
    *,
    name: str | None = None,
    location: str | None = None,
    default_branch: str | None = None,
) -> dict[str, Any] | None:
    """Edit a source's display/scan fields (COALESCE keeps unspecified ones)."""
    with db.connection() as conn:
        row = conn.execute(
            """
            UPDATE sources SET
                name = COALESCE(%s, name),
                location = COALESCE(%s, location),
                default_branch = COALESCE(%s, default_branch)
            WHERE id = %s
            RETURNING *
            """,
            (name, location, default_branch, source_id),
        ).fetchone()
        conn.commit()
    return row


def set_source_active(source_id: int, active: bool) -> None:
    db.execute("UPDATE sources SET active = %s WHERE id = %s", (active, source_id))


def delete_source(source_id: int) -> None:
    db.execute("DELETE FROM sources WHERE id = %s", (source_id,))


def sources_due_for_check(limit: int = 200) -> list[dict[str, Any]]:
    """Active sources whose cheap change-probe is due (per scope cadence)."""
    return db.fetchall(
        """
        SELECT s.*, sc.config AS scope_config, sc.connector AS connector,
               sc.families AS scope_families
        FROM sources s
        JOIN scopes sc ON sc.id = s.scope_id
        WHERE s.active AND sc.enabled
          AND (s.last_checked_at IS NULL
               OR s.last_checked_at < now()
                  - make_interval(secs => sc.rescan_interval_seconds))
        ORDER BY s.last_checked_at NULLS FIRST
        LIMIT %s
        """,
        (limit,),
    )


def mark_source_checked(source_id: int, revision: str | None) -> None:
    db.execute(
        "UPDATE sources SET last_checked_at = now(), last_revision = COALESCE(%s, last_revision) "
        "WHERE id = %s",
        (revision, source_id),
    )


# --------------------------------------------------------------------------- #
# Jobs / queue - shared implementation. The kruncher fleet runs both queues.
# --------------------------------------------------------------------------- #

enqueue_scan = _jobs.enqueue_scan
heartbeat = _jobs.heartbeat
persist_success = _jobs.persist_success
fail_job = _jobs.fail_job
fail_adhoc = _jobs.fail_adhoc
reap_stale_jobs = _jobs.reap_stale_jobs
relaunch_job = _jobs.relaunch_job
cancel_job = _jobs.cancel_job
is_cancelled = _jobs.is_cancelled
get_job = _jobs.get_job
get_job_attempts = _jobs.get_job_attempts
queue_depth_by_origin = _jobs.queue_depth_by_origin


def claim_job(
    worker_id: str, *, origins: tuple[str, ...] = ("discovery", "adhoc")
) -> dict[str, Any] | None:
    return _jobs.claim_job(worker_id, origins=origins)


def list_jobs(
    status: str | None = None,
    source_id: int | None = None,
    origin: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List jobs from both queues by default; pass ``origin`` to scope to one
    (``'discovery'`` = periodic, ``'adhoc'`` = manual)."""
    return _jobs.list_jobs(
        status=status, source_id=source_id, origin=origin, limit=limit
    )


def queue_depth(origin: str | None = None) -> dict[str, int]:
    """Status counts across both queues by default; pass ``origin`` for one."""
    return _jobs.queue_depth(origin=origin)
