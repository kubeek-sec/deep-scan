"""Ad-hoc (manual queue) job execution: materialize → run_scan → write reports
→ persist. This is the *adhoc half* of the kruncher worker - the fleet calls
``run_adhoc_job`` for every ``origin='adhoc'`` job (API/MCP submissions), the
same way it runs ``origin='discovery'`` jobs through its connector path.

* ``run_adhoc_job`` - the full materialize/scan/persist for one already-claimed
  ad-hoc job (used by the kruncher worker fleet).
* ``run_job_inline`` - the same, but records a terminal failure on error and
  re-raises, for callers that run a single job synchronously and want the report
  back (the MCP server's local-stdio path).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from pathlib import Path
from typing import Any

from deepscan_core import Family, Mode, fingerprint, run_scan
from deepscan_core.reporting import write_report, write_triage

from . import config, ramfs, store, uploads
from .materialize import materialize_adhoc
from .progress import JobProgress

log = logging.getLogger("deepscan.jobs.worker")

# How often the background pump flushes the live step snapshot to the DB.
_PROGRESS_INTERVAL = 1.5
# How often the pump bumps ``heartbeat_at`` even when nothing changed, so a long,
# event-free phase (e.g. the analysis scanner building a big code graph) is never
# reaped as stale. Must stay well under ``config.lease_seconds()`` (default 1800).
_HEARTBEAT_INTERVAL = 30.0


class _JobCancelled(Exception):
    """Unwinds a job whose operator cancelled it mid-scan, so the worker stops
    before writing/persisting a partial report. The row is already ``cancelled``."""


def _report_dir(job: dict[str, Any]) -> Path:
    return config.job_report_dir(job["id"])


def _target_dir(job: dict[str, Any]) -> Path:
    # Retained per-job source store, bucketed by surface (sources/api/job-<id> …).
    return config.job_source_dir(
        job["id"], origin=job.get("origin"), surface=job.get("surface")
    )


def _provenance(
    job: dict[str, Any],
    source_path: str,
    *,
    fingerprint: str | None = None,
    git_commit: str | None = None,
) -> dict[str, Any]:
    """Provenance recorded on the report and shown in its 'Source' section.

    ``source`` is the human-facing origin (git URL / uploaded filename / local
    path / target URL); ``source_path`` is where the analyzed files are retained
    on the shared volume; ``fingerprint`` is the content SHA-512 of the scanned
    tree and ``git_commit`` the checked-out commit when known. Unset keys drop.
    """
    source = job.get("target")
    if job.get("target_type") == "zip" and job.get("upload_id"):
        row = uploads.get_upload(job["upload_id"])
        if row and row.get("filename"):
            source = row["filename"]
    prov = {
        "origin": job.get("origin"),
        "surface": job.get("surface"),
        "target_type": job.get("target_type"),
        "source": source,
        "upload_id": job.get("upload_id"),
        "source_path": source_path,
        "git_commit": git_commit or job.get("target_revision"),
        "fingerprint": fingerprint,
    }
    return {k: v for k, v in prov.items() if v is not None}


def _persist_progress(job_id: int, prog: JobProgress) -> None:
    try:
        store.update_progress(
            job_id, completion=prog.completion(), stage=prog.stage(), steps=prog.snapshot()
        )
    except Exception:  # noqa: BLE001 - progress is best-effort, never fail the scan
        log.debug("progress persist failed for job %s", job_id, exc_info=True)


async def _progress_pump(
    job_id: int, prog: JobProgress, cancel_event: threading.Event | None = None
) -> None:
    """Keep the job alive and its live view fresh while a scan runs.

    Every ``_PROGRESS_INTERVAL`` we flush the step snapshot *when it changed*
    (which also bumps ``heartbeat_at``). When nothing changed we still bump the
    heartbeat every ``_HEARTBEAT_INTERVAL`` with a cheap UPDATE, so a long phase
    that emits no progress events - e.g. the ``analysis`` scanner building the
    code graph over a large repo - is never reaped as a stale lease.

    The same loop polls for an operator cancel: when the job row turns
    ``cancelled`` it sets ``cancel_event``, which long CPU-bound scanners observe
    (via ``ctx.should_stop``) to abort cooperatively within a couple of seconds."""
    last_beat = time.monotonic()
    while True:
        await asyncio.sleep(_PROGRESS_INTERVAL)
        if cancel_event is not None and not cancel_event.is_set():
            if await asyncio.to_thread(store.is_cancelled, job_id):
                cancel_event.set()
        if prog.take_dirty():
            await asyncio.to_thread(_persist_progress, job_id, prog)
            last_beat = time.monotonic()
        elif time.monotonic() - last_beat >= _HEARTBEAT_INTERVAL:
            await asyncio.to_thread(store.heartbeat, job_id)
            last_beat = time.monotonic()


async def run_scan_tracked(
    job_id: int,
    prog: JobProgress,
    target: str,
    *,
    cancel_event: threading.Event | None = None,
    **scan_kwargs,
):
    """Run ``run_scan`` wired to ``prog`` with a background snapshot pump so the
    per-scanner steps update live in the DB while the scan runs. ``cancel_event``
    (when given) lets the pump signal a cooperative abort on operator cancel."""
    pump = asyncio.create_task(_progress_pump(job_id, prog, cancel_event))
    try:
        return await run_scan(
            target, on_progress=prog.on_scan_event, cancel_event=cancel_event, **scan_kwargs
        )
    finally:
        pump.cancel()
        await asyncio.gather(pump, return_exceptions=True)
        await asyncio.to_thread(_persist_progress, job_id, prog)  # final flush


async def run_adhoc_job(
    job: dict[str, Any], *, allow_private: bool = True, allow_local_paths: bool = True
):
    """Materialize, scan, write all report formats and persist. Returns the
    ``Report``. Raises on failure - the caller records it (pool / inline).

    Progress is tracked step-by-step (acquire → each scanner → report) and
    streamed to ``scan_jobs.steps`` so a dashboard can follow it live."""
    started = time.monotonic()
    prog = JobProgress()
    prog.add_phase("acquire", "Acquire source")
    prog.add_phase("report", "Write report")
    # Set by the progress pump when an operator cancels the job; long CPU-bound
    # scanners poll it (via ``ctx.should_stop``) to abort within a few seconds.
    cancel_event = threading.Event()
    try:
        prog.start("acquire")
        await asyncio.to_thread(_persist_progress, job["id"], prog)
        scan_target = await materialize_adhoc(
            job["target_type"],
            job["target"],
            _target_dir(job),
            allow_private=allow_private,
            allow_local_paths=allow_local_paths,
        )
        # Record where the analyzed files are retained *before* the scan, so even
        # a failed scan leaves a pointer to its source on the job. URL targets
        # have no files on disk, so nothing to retain/fingerprint.
        is_static = job.get("target_type") != "url"
        if is_static:
            await asyncio.to_thread(
                store.set_source_location,
                job["id"],
                source_path=scan_target,
                upload_id=job.get("upload_id"),
            )
        # The commit is read from the *original* source (the RAM copy excludes
        # .git); None when there is no git work tree - the fingerprint covers it.
        commit = (
            await asyncio.to_thread(fingerprint.git_commit, scan_target)
            if is_static
            else None
        )
        prog.finish("acquire")
        report_dir = _report_dir(job)
        fp = None
        # Scan over a RAM-backed copy of the source for fast I/O; a no-op for URL
        # targets and when RAM staging is disabled/unavailable (scans in place).
        with ramfs.staged_for_scan(scan_target) as scan_path:
            if is_static:
                # Fingerprint the scanned tree on the fast RAM copy, before scanning.
                fp = await asyncio.to_thread(fingerprint.fingerprint_tree, scan_path)
            report = await run_scan_tracked(
                job["id"],
                prog,
                scan_path,
                cancel_event=cancel_event,
                mode=Mode(job["mode"]) if job.get("mode") else None,
                families=[Family(f) for f in (job.get("families") or [])] or None,
                scanners=(job.get("scanners") or None),
                raw_dir=report_dir / "raw",
                allow_private_urls=allow_private,
                surface=job.get("surface") or "jobs",
            )
        # Operator cancelled while scanning: stop before writing/persisting a
        # partial report. The job row is already terminal ('cancelled').
        if cancel_event.is_set() or await asyncio.to_thread(store.is_cancelled, job["id"]):
            raise _JobCancelled(job["id"])
        if is_static and (fp or commit):
            await asyncio.to_thread(
                store.set_scan_identity, job["id"], fingerprint=fp, git_commit=commit
            )
        report.provenance = _provenance(job, scan_target, fingerprint=fp, git_commit=commit)
        prog.start("report")
        await asyncio.to_thread(_persist_progress, job["id"], prog)
        await asyncio.to_thread(write_report, report, report_dir)
        await asyncio.to_thread(write_triage, report, report_dir)
        prog.finish("report")
        store.persist_report(
            job, report, report_dir=str(report_dir), duration=time.monotonic() - started
        )
        await asyncio.to_thread(_persist_progress, job["id"], prog)  # final, all-done snapshot
        return report
    except _JobCancelled:
        # Benign operator cancel - leave the steps as-is (don't mark them errored)
        # and let the caller finalize the job as cancelled.
        log.info("Manual job %s cancelled mid-scan - no report written.", job["id"])
        raise
    except Exception as exc:  # noqa: BLE001 - record which step was in-flight, then re-raise
        prog.fail_running(detail=f"{type(exc).__name__}: {exc}")
        await asyncio.to_thread(_persist_progress, job["id"], prog)
        raise


async def run_job_inline(
    job: dict[str, Any], *, allow_private: bool = True, allow_local_paths: bool = True
):
    """Run a single already-claimed ad-hoc job; record a terminal failure."""
    try:
        return await run_adhoc_job(
            job, allow_private=allow_private, allow_local_paths=allow_local_paths
        )
    except _JobCancelled:
        return None  # operator cancel - the row is already 'cancelled'
    except Exception as exc:  # noqa: BLE001 - turn into a tracked failure
        if store.is_cancelled(job["id"]):
            return None  # cancelled mid-scan - don't overwrite with 'failed'
        store.fail_adhoc(job, error=f"{type(exc).__name__}: {exc}")
        raise
