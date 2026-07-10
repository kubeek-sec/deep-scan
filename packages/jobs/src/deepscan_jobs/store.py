"""Shared data-access layer for the scan-job queue and results.

Concurrency model (all enforced by Postgres, no external broker):

* ``claim_job`` uses ``FOR UPDATE SKIP LOCKED`` so any number of workers can
  pull from the same queue without ever handing the same job to two workers.
  A worker passes the ``origins`` it can run (``discovery`` for kruncher,
  ``adhoc`` for the API) so it never claims a job it cannot materialize.
* ``persist_success`` writes the result, its findings, the job's terminal state
  and the source's bookkeeping in **one transaction**.
* Ad-hoc jobs (API/MCP) carry the target inline and persist a report dir +
  summary on the job; discovery jobs (kruncher) persist into scan_results.

Scope/source CRUD stays in ``deepscan_kruncher.store`` (discovery concerns);
this module only touches ``sources`` for per-job bookkeeping.
"""

from __future__ import annotations

import json
from typing import Any

import psycopg

from deepscan_core import Report

from . import config, db
from .models import (  # noqa: F401 (re-exported)
    OPEN_STATUSES,
    PRIORITY_ADHOC,
    QUEUE_MANUAL,
    TERMINAL_STATUSES,
)


# --------------------------------------------------------------------------- #
# NUL-byte sanitization. Scanner output can carry NUL (0x00) bytes (binary-ish
# files, odd tool stdout); PostgreSQL TEXT *and* JSONB reject them ("cannot
# contain NUL"). Strip them right before they hit the DB so persistence never
# fails on a stray byte.
# --------------------------------------------------------------------------- #


def _nul_safe(value):
    """Strip NUL bytes from a string; pass anything else through unchanged."""
    return value.replace("\x00", "") if isinstance(value, str) else value


def _nul_safe_list(values):
    return [_nul_safe(v) for v in values] if values else values


def _json_nul_safe(obj):
    """Recursively strip NUL from a JSON-able structure (for JSONB columns -
    Postgres JSONB also rejects ``\\u0000`` inside string values)."""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {k: _json_nul_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_nul_safe(v) for v in obj]
    return obj


def _get_source(source_id: int | None) -> dict[str, Any] | None:
    if source_id is None:
        return None
    return db.fetchone("SELECT * FROM sources WHERE id = %s", (source_id,))


# --------------------------------------------------------------------------- #
# Discovery jobs (kruncher)
# --------------------------------------------------------------------------- #


def enqueue_scan(
    source_id: int,
    *,
    target_revision: str | None,
    branch: str | None = None,
    priority: int = 100,
    max_attempts: int | None = None,
) -> dict[str, Any]:
    """Supersede a source's open jobs, then insert a fresh queued discovery job."""
    max_att = max_attempts or config.max_attempts()
    with db.connection() as conn:
        conn.execute(
            "UPDATE scan_jobs SET status = 'superseded', updated_at = now() "
            "WHERE source_id = %s AND status = ANY(%s)",
            (source_id, list(OPEN_STATUSES)),
        )
        row = conn.execute(
            """
            INSERT INTO scan_jobs (source_id, origin, status, target_revision, branch,
                                   priority, max_attempts)
            VALUES (%s, 'discovery', 'queued', %s, %s, %s, %s)
            RETURNING *
            """,
            (source_id, target_revision, branch, priority, max_att),
        ).fetchone()
        conn.execute(
            "UPDATE sources SET last_revision = COALESCE(%s, last_revision) WHERE id = %s",
            (target_revision, source_id),
        )
        conn.commit()
    return row


# --------------------------------------------------------------------------- #
# Ad-hoc jobs (API / MCP)
# --------------------------------------------------------------------------- #


def create_adhoc_job(
    *,
    target_type: str,
    target: str,
    mode: str | None = None,
    families: list[str] | None = None,
    scanners: list[str] | None = None,
    surface: str | None = None,
    upload_id: str | None = None,
    max_attempts: int = 1,
    priority: int = PRIORITY_ADHOC,
    start_running: bool = False,
    worker_id: str | None = None,
) -> dict[str, Any]:
    """Insert an ad-hoc (origin='adhoc') job - the *manual* queue.

    Manual jobs default to a higher priority than periodic ones so they run
    first; the kruncher worker also drains the manual queue ahead of the
    periodic one (see :func:`claim_job`).

    ``start_running=True`` inserts it already claimed (status='running',
    attempt=1) so the worker fleet never picks it up - used when the caller runs
    the job inline itself (e.g. an MCP tool that returns the report directly).
    """
    common = (
        target_type, target, mode, families or [], scanners or [],
        surface, max_attempts, priority, upload_id,
    )
    with db.connection() as conn:
        if start_running:
            row = conn.execute(
                """
                INSERT INTO scan_jobs (origin, status, target_type, target, mode,
                    families, scanners, surface, max_attempts, priority, upload_id,
                    attempt, locked_by, locked_at, heartbeat_at, started_at, stage)
                VALUES ('adhoc', 'running', %s, %s, %s, %s, %s, %s, %s, %s, %s, 1,
                    %s, now(), now(), now(), 'claimed')
                RETURNING *
                """,
                (*common, worker_id or config.worker_id()),
            ).fetchone()
        else:
            row = conn.execute(
                """
                INSERT INTO scan_jobs (origin, status, target_type, target, mode,
                    families, scanners, surface, max_attempts, priority, upload_id)
                VALUES ('adhoc', 'queued', %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                common,
            ).fetchone()
        conn.commit()
    return row


def set_source_location(
    job_id: int, *, source_path: str, upload_id: str | None = None
) -> None:
    """Record where a job's analyzed files are retained on the shared volume.

    Called by the workers right after the target is materialized - before the
    scan runs - so even a failed scan keeps a pointer to its retained source.
    ``upload_id`` is preserved when not supplied (set at submit time for zips).
    """
    db.execute(
        "UPDATE scan_jobs SET source_path = %s, upload_id = COALESCE(%s, upload_id), "
        "updated_at = now() WHERE id = %s",
        (_nul_safe(source_path), upload_id, job_id),
    )


def set_scan_identity(
    job_id: int, *, fingerprint: str | None = None, git_commit: str | None = None
) -> None:
    """Record the scanned tree's content fingerprint (SHA-512) and git commit.

    Computed before the scan (on the fast RAM copy); ``COALESCE`` keeps any value
    already set so a partial update never clears the other identifier.
    """
    db.execute(
        "UPDATE scan_jobs SET fingerprint = COALESCE(%s, fingerprint), "
        "git_commit = COALESCE(%s, git_commit), updated_at = now() WHERE id = %s",
        (_nul_safe(fingerprint), _nul_safe(git_commit), job_id),
    )


def persist_report(
    job: dict[str, Any], report: Report, *, report_dir: str, duration: float | None = None
) -> None:
    """Mark an ad-hoc job done with its summary + report directory."""
    summary = report.to_dict()["summary"]
    with db.connection() as conn:
        conn.execute(
            "UPDATE scan_jobs SET status='done', completion=100, stage='done', "
            "error=NULL, summary=%s, report_dir=%s, finished_at=now(), updated_at=now() "
            "WHERE id=%s",
            (json.dumps(_json_nul_safe(summary)), str(report_dir), job["id"]),
        )
        _record_attempt(conn, job, status="done", error=None, log=None, duration=duration)
        conn.commit()


def fail_adhoc(
    job: dict[str, Any], *, error: str, log: str | None = None, duration: float | None = None
) -> None:
    """Terminal failure for an ad-hoc job (no retry, matches the old API)."""
    with db.connection() as conn:
        conn.execute(
            "UPDATE scan_jobs SET status='failed', stage='failed', error=%s, "
            "locked_by=NULL, finished_at=now(), updated_at=now() WHERE id=%s",
            (_nul_safe(error[:4000]), job["id"]),
        )
        _record_attempt(conn, job, status="failed", error=error, log=log, duration=duration)
        conn.commit()


def delete_job(job_id: int) -> None:
    db.execute("DELETE FROM scan_jobs WHERE id = %s", (job_id,))


# A job stranded ``running`` by a crashed worker is recovered by the lease-based
# ``reap_stale_jobs`` (run by the kruncher scheduler), not a startup sweep - with
# a multi-replica fleet, one replica restarting must not fail jobs its peers own.


# --------------------------------------------------------------------------- #
# Shared queue lifecycle
# --------------------------------------------------------------------------- #


def claim_job(
    worker_id: str, *, origins: tuple[str, ...] = ("discovery", "adhoc")
) -> dict[str, Any] | None:
    """Atomically claim the next runnable job for ``worker_id`` (or ``None``).

    When a worker accepts both queues, the *manual* queue (origin='adhoc') is
    always preferred over the *periodic* one: ``ORDER BY (origin <> 'adhoc')``
    sorts manual jobs (false=0) ahead of periodic jobs (true=1), then by
    priority and arrival. So an operator-submitted scan jumps ahead of any
    queued periodic work, and only waits for a worker to free up.
    """
    with db.connection() as conn:
        job = conn.execute(
            """
            WITH claimed AS (
                SELECT id FROM scan_jobs
                WHERE status = 'queued' AND available_at <= now()
                  AND origin = ANY(%s)
                ORDER BY (origin <> %s), priority, available_at
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE scan_jobs j
               SET status = 'running',
                   attempt = j.attempt + 1,
                   locked_by = %s,
                   locked_at = now(),
                   heartbeat_at = now(),
                   started_at = COALESCE(j.started_at, now()),
                   completion = 0,
                   stage = 'claimed',
                   updated_at = now()
              FROM claimed
             WHERE j.id = claimed.id
            RETURNING j.*
            """,
            (list(origins), QUEUE_MANUAL, worker_id),
        ).fetchone()
        conn.commit()
    if job is None:
        return None
    job["source"] = _get_source(job.get("source_id"))
    return job


def heartbeat(job_id: int, *, completion: int | None = None, stage: str | None = None) -> None:
    db.execute(
        "UPDATE scan_jobs SET heartbeat_at = now(), "
        "completion = COALESCE(%s, completion), stage = COALESCE(%s, stage), "
        "updated_at = now() WHERE id = %s",
        (completion, stage, job_id),
    )


def update_progress(
    job_id: int,
    *,
    completion: int | None = None,
    stage: str | None = None,
    steps: dict[str, Any] | None = None,
) -> None:
    """Heartbeat + persist the live step snapshot to ``scan_jobs.steps``.

    Also bumps ``heartbeat_at`` so a long, actively-progressing scan is never
    reaped as stale. ``steps`` is the JSON-serializable snapshot from
    :class:`deepscan_jobs.progress.JobProgress`.
    """
    db.execute(
        "UPDATE scan_jobs SET heartbeat_at = now(), updated_at = now(), "
        "completion = COALESCE(%s, completion), stage = COALESCE(%s, stage), "
        "steps = COALESCE(%s::jsonb, steps) WHERE id = %s",
        (completion, _nul_safe(stage), json.dumps(_json_nul_safe(steps)) if steps is not None else None, job_id),
    )


def _record_attempt(
    conn: psycopg.Connection,
    job: dict[str, Any],
    *,
    status: str,
    error: str | None,
    log: str | None,
    duration: float | None,
) -> None:
    conn.execute(
        """
        INSERT INTO job_attempts (job_id, attempt, status, error, log, worker,
                                  started_at, duration_seconds)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            job["id"],
            job.get("attempt") or 1,
            status,
            _nul_safe((error or "")[:4000]) or None,
            _nul_safe((log or "")[:8000]) or None,
            job.get("locked_by"),
            job.get("started_at"),
            duration,
        ),
    )


def persist_success(
    job: dict[str, Any], report: Report, *, duration: float, report_dir: str | None = None
) -> dict[str, Any]:
    """Discovery: write result + findings, mark job done, update the source.

    ``report_dir`` is recorded on the job so the on-disk reports a periodic scan
    wrote (``reports/job-<id>``) are discoverable like an ad-hoc job's.
    """
    d = report.to_dict()
    summary = d["summary"]
    totals = summary["severity_totals"]
    with db.connection() as conn:
        result = conn.execute(
            """
            INSERT INTO scan_results (job_id, source_id, revision, mode,
                duration_seconds, tools_ran, tools_skipped, tools_error,
                total_findings, crit, high, med, low, info, summary)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING *
            """,
            (
                job["id"],
                job["source_id"],
                job.get("target_revision"),
                d["meta"]["mode"],
                duration,
                summary["tools_run"],
                summary["tools_skipped"],
                summary["tools_error"],
                summary["deduplicated_findings"],
                totals["critical"],
                totals["high"],
                totals["medium"],
                totals["low"],
                totals["info"],
                json.dumps(_json_nul_safe(summary)),
            ),
        ).fetchone()
        rows = [
            (
                result["id"],
                job["source_id"],
                _nul_safe(f.fingerprints[0] if f.fingerprints else ""),
                f.severity.value,
                _nul_safe_list(f.families),
                _nul_safe_list(f.tools),
                _nul_safe_list(f.rules),
                _nul_safe_list(f.cwes),
                _nul_safe(f.message[:2000]),
                _nul_safe(f.location[:1000]),
                f.occurrences,
            )
            for f in report.findings
        ]
        if rows:
            conn.cursor().executemany(
                """
                INSERT INTO findings (result_id, source_id, fingerprint, severity,
                    families, tools, rules, cwes, message, location, occurrences)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                rows,
            )
        conn.execute(
            "UPDATE scan_jobs SET status='done', completion=100, stage='done', "
            "error=NULL, report_dir=COALESCE(%s, report_dir), summary=%s, "
            "finished_at=now(), updated_at=now() WHERE id=%s",
            (report_dir, json.dumps(_json_nul_safe(summary)), job["id"]),
        )
        conn.execute(
            "UPDATE sources SET last_scanned_revision = %s, last_scanned_at = now() "
            "WHERE id = %s",
            (job.get("target_revision"), job["source_id"]),
        )
        _record_attempt(conn, job, status="done", error=None, log=None, duration=duration)
        conn.commit()
    return result


def fail_job(
    job: dict[str, Any],
    *,
    error: str,
    log: str | None = None,
    duration: float | None = None,
) -> str:
    """Discovery: apply retry/backoff or dead-letter. Returns the new status."""
    attempt = job["attempt"]
    max_att = job["max_attempts"]
    with db.connection() as conn:
        if attempt >= max_att:
            new_status = "dead"
            conn.execute(
                "UPDATE scan_jobs SET status='dead', stage='failed', error=%s, "
                "finished_at=now(), updated_at=now() WHERE id=%s",
                (_nul_safe(error[:4000]), job["id"]),
            )
        else:
            new_status = "queued"
            backoff = config.RETRY_BACKOFF_SECONDS[
                min(attempt - 1, len(config.RETRY_BACKOFF_SECONDS) - 1)
            ]
            conn.execute(
                "UPDATE scan_jobs SET status='queued', stage='retry-wait', error=%s, "
                "locked_by=NULL, available_at = now() + make_interval(secs => %s), "
                "updated_at=now() WHERE id=%s",
                (_nul_safe(error[:4000]), backoff, job["id"]),
            )
        _record_attempt(conn, job, status="failed", error=error, log=log, duration=duration)
        conn.commit()
    return new_status


def reap_stale_jobs(lease_seconds: int | None = None) -> int:
    """Fail/requeue jobs (both queues) whose worker stopped heart-beating.

    With execution moved entirely onto the kruncher fleet, a crashed worker can
    strand a running job from *either* queue. Periodic (discovery) jobs go
    through retry/backoff; manual (adhoc) jobs are failed terminally, matching
    their no-retry contract.
    """
    lease = lease_seconds or config.lease_seconds()
    stale = db.fetchall(
        "SELECT * FROM scan_jobs WHERE status='running' "
        "AND heartbeat_at < now() - make_interval(secs => %s)",
        (lease,),
    )
    for job in stale:
        error = f"Lease expired (no heartbeat for >{lease}s)."
        if job["origin"] == QUEUE_MANUAL:
            fail_adhoc(job, error=error)
        else:
            fail_job(job, error=error)
    return len(stale)


def relaunch_job(job_id: int) -> dict[str, Any] | None:
    """Admin action: put a terminal job back on the queue, fresh."""
    with db.connection() as conn:
        row = conn.execute(
            "UPDATE scan_jobs SET status='queued', attempt=0, completion=0, "
            "stage=NULL, error=NULL, locked_by=NULL, available_at=now(), "
            "finished_at=NULL, updated_at=now() "
            "WHERE id=%s AND status = ANY(%s) RETURNING *",
            (job_id, list(TERMINAL_STATUSES)),
        ).fetchone()
        conn.commit()
    return row


def cancel_job(job_id: int) -> dict[str, Any] | None:
    """Cancel a job. A ``queued``/``failed`` job is cancelled outright; a
    ``running`` one is *flagged* cancelled - the worker holding it polls the
    status and aborts the scan cooperatively (see ``worker._progress_pump``),
    then leaves the row terminal. Returns ``{prev_status, locked_by}`` of the
    affected job, or ``None`` when it was not in a cancellable state."""
    return db.fetchone(
        """
        WITH prev AS (
            SELECT id, status, locked_by FROM scan_jobs WHERE id = %s FOR UPDATE
        )
        UPDATE scan_jobs j
           SET status='cancelled', stage='cancelled', updated_at=now()
          FROM prev
         WHERE j.id = prev.id
           AND prev.status IN ('queued','failed','running')
        RETURNING prev.status AS prev_status, prev.locked_by AS locked_by
        """,
        (job_id,),
    )


def is_cancelled(job_id: int) -> bool:
    """True when the job has been moved to ``cancelled`` (polled mid-scan by the
    worker so a running job can stop cooperatively)."""
    row = db.fetchone("SELECT status FROM scan_jobs WHERE id = %s", (job_id,))
    return bool(row) and row["status"] == "cancelled"


def _job_filters(
    status: str | None, source_id: int | None, origin: str | None
) -> tuple[str, list[Any]]:
    """Shared WHERE clause for list_jobs / count_jobs (keeps them consistent)."""
    clauses, params = [], []
    if status:
        clauses.append("j.status = %s")
        params.append(status)
    if source_id is not None:
        clauses.append("j.source_id = %s")
        params.append(source_id)
    if origin:
        clauses.append("j.origin = %s")
        params.append(origin)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def list_jobs(
    status: str | None = None,
    source_id: int | None = None,
    origin: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    where, params = _job_filters(status, source_id, origin)
    params.append(max(1, limit))
    params.append(max(0, offset))
    return db.fetchall(
        f"""
        SELECT j.*, s.name AS source_name, s.kind AS source_kind, s.scope_id
        FROM scan_jobs j LEFT JOIN sources s ON s.id = j.source_id
        {where}
        ORDER BY j.created_at DESC, j.id DESC
        LIMIT %s OFFSET %s
        """,
        tuple(params),
    )


def count_jobs(
    status: str | None = None,
    source_id: int | None = None,
    origin: str | None = None,
) -> int:
    """Total rows matching the same filters as :func:`list_jobs` (for paging)."""
    where, params = _job_filters(status, source_id, origin)
    row = db.fetchone(f"SELECT count(*) AS n FROM scan_jobs j {where}", tuple(params))
    return (row or {}).get("n", 0)


def get_job(job_id: int) -> dict[str, Any] | None:
    return db.fetchone("SELECT * FROM scan_jobs WHERE id = %s", (job_id,))


def active_job_ids() -> set[int]:
    """Ids of jobs that are NOT in a terminal state (queued/running/...). Their
    retained sources/reports must never be pruned - a scan may still be using
    them, or a result is about to be written."""
    rows = db.fetchall(
        "SELECT id FROM scan_jobs "
        "WHERE status NOT IN ('done','failed','cancelled','superseded')"
    )
    return {r["id"] for r in rows}


def get_job_attempts(job_id: int) -> list[dict[str, Any]]:
    return db.fetchall(
        "SELECT * FROM job_attempts WHERE job_id = %s ORDER BY attempt", (job_id,)
    )


def queue_depth(origin: str | None = None) -> dict[str, int]:
    where = "WHERE origin = %s" if origin else ""
    params: tuple[Any, ...] = (origin,) if origin else ()
    rows = db.fetchall(
        f"SELECT status, count(*) AS n FROM scan_jobs {where} GROUP BY status", params
    )
    return {r["status"]: r["n"] for r in rows}


def queue_depth_by_origin() -> dict[str, dict[str, int]]:
    """Status counts split by queue: ``{origin: {status: n}}``.

    Lets a dashboard show the manual and periodic queues side by side.
    """
    rows = db.fetchall(
        "SELECT origin, status, count(*) AS n FROM scan_jobs GROUP BY origin, status"
    )
    out: dict[str, dict[str, int]] = {}
    for r in rows:
        out.setdefault(r["origin"], {})[r["status"]] = r["n"]
    return out
