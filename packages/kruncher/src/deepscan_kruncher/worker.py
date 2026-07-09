"""The worker: the expensive half. The single executor for *both* scan queues.

Each iteration claims one job and runs it to completion:

* **manual** queue (``origin='adhoc'`` - API / MCP submissions): materialize the
  ad-hoc target (git/url/zip/path), scan, write the report files, persist the
  summary on the job. Delegated to :mod:`deepscan_jobs.worker`.
* **periodic** queue (``origin='discovery'`` - scheduler-enqueued): materialize
  via the source's connector, scan, persist findings into the ASPM tables.

The manual queue is always preferred (see ``store.claim_job``), so an
operator's scan never waits behind queued periodic work.

A worker never raises out of ``process_one``: every failure is turned into a
tracked failure - retry/dead-letter for periodic jobs, a terminal ``failed``
for manual ones (which carry no retries).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from pathlib import Path
from typing import Any

from deepscan_core import Family, Mode, fingerprint
from deepscan_core.reporting import write_report, write_triage
from deepscan_input_connector_base import ConnectorError, DiscoveredSource
from deepscan_jobs import config as jobs_config
from deepscan_jobs import ramfs as jobs_ramfs
from deepscan_jobs import store as jobs_store
from deepscan_jobs.models import QUEUE_MANUAL
from deepscan_jobs.progress import JobProgress
from deepscan_jobs.worker import run_adhoc_job, run_scan_tracked

from . import config, store
from .connectors import get as get_connector

log = logging.getLogger("deepscan.kruncher.worker")

# The worker fleet drains both queues; the manual one is preferred in claim
# ordering. (Listing 'adhoc' first is cosmetic - the SQL does the prioritizing.)
_QUEUES = ("adhoc", "discovery")


def _discovered(source: dict[str, Any]) -> DiscoveredSource:
    return DiscoveredSource(
        external_id=source["external_id"],
        kind=source["kind"],
        name=source["name"],
        location=source["location"],
        default_branch=source["default_branch"],
        metadata=source["metadata"] or {},
    )


def process_one(worker_id: str | None = None) -> bool:
    """Claim and process a single job from either queue. Returns ``True`` if a
    job was handled. The manual (adhoc) queue is preferred (claim ordering)."""
    wid = worker_id or config.worker_id()
    job = store.claim_job(wid, origins=_QUEUES)
    if job is None:
        return False
    log.info(
        "Worker %s claimed %s job %s (attempt %s)",
        wid, job["origin"], job["id"], job["attempt"],
    )
    if job["origin"] == QUEUE_MANUAL:
        _run_adhoc_job(job)
    else:
        _run_discovery_job(job)
    return True


def _run_adhoc_job(job: dict[str, Any]) -> None:
    """Run a manual (API/MCP) scan via the shared ad-hoc executor and record a
    terminal failure if it raises (manual jobs carry no retries)."""
    try:
        asyncio.run(
            run_adhoc_job(
                job,
                allow_private=config.allow_private_targets(),
                allow_local_paths=config.allow_local_paths(),
            )
        )
        log.info("Manual job %s done.", job["id"])
    except Exception as exc:  # noqa: BLE001 - convert to a tracked failure
        # An operator cancel surfaces here as an exception; the row is already
        # 'cancelled', so don't overwrite it with a 'failed' terminal state.
        if jobs_store.is_cancelled(job["id"]):
            log.info("Manual job %s cancelled by operator; stopped.", job["id"])
            return
        jobs_store.fail_adhoc(job, error=f"{type(exc).__name__}: {exc}")
        log.warning("Manual job %s failed: %s", job["id"], exc)


def _run_discovery_job(job: dict[str, Any]) -> None:
    started = time.monotonic()
    source = job["source"]
    # Retained per-job analyzed-source store on the shared volume (so the API can
    # find discovery sources too), replacing the old worker-local work_dir.
    dest = jobs_config.job_source_dir(job["id"], origin="discovery")
    report_dir = jobs_config.job_report_dir(job["id"])
    log_excerpt = ""
    prog = JobProgress()
    prog.add_phase("acquire", "Acquire source")
    prog.add_phase("report", "Persist results")
    try:
        scope = store.get_scope(source["scope_id"])
        if scope is None:
            raise ConnectorError("scope vanished before scan")
        connector = get_connector(scope["connector"])

        prog.start("acquire")
        jobs_store.update_progress(
            job["id"], completion=prog.completion(), stage="acquire", steps=prog.snapshot()
        )
        if dest.exists():
            # A retry re-clones fresh into the same retained dir. ``dest`` is
            # always under sources/discovery/ - never an in-place directory
            # source - so this rmtree can never touch an operator's real dir.
            shutil.rmtree(dest, ignore_errors=True)
        target = connector.materialize(
            _discovered(source), job.get("target_revision"), dest, scope["config"]
        )
        # Keep ALL retrieved files under sources/discovery/job-<id> for posterity.
        # Most connectors clone/copy into ``dest``; a directory connector scanning
        # in place (snapshot=false) returns the source path itself - snapshot it
        # into ``dest`` so the exact files scanned are retained (the operator's
        # own directory is copied from, never moved or deleted).
        if Path(target).resolve() != dest.resolve():
            shutil.copytree(target, dest, symlinks=True, dirs_exist_ok=True)
            target = dest
        # Record where the files are retained, before the scan, so a failed scan
        # still points at its source.
        jobs_store.set_source_location(job["id"], source_path=str(target))
        # The commit is the enqueued revision (from ls-remote) when known, else
        # read from a .git in the materialized tree; None for plain directories.
        commit = job.get("target_revision") or fingerprint.git_commit(str(target))
        prog.finish("acquire")

        families = [Family(f) for f in (scope.get("families") or [])] or None
        # Scan over a RAM-backed copy for fast I/O (no-op when staging is off).
        with jobs_ramfs.staged_for_scan(str(target)) as scan_path:
            # Fingerprint the scanned tree on the fast RAM copy, before scanning.
            fp = fingerprint.fingerprint_tree(scan_path)
            report = asyncio.run(
                run_scan_tracked(
                    job["id"], prog, scan_path,
                    mode=Mode.STATIC, families=families, surface="kruncher",
                    raw_dir=report_dir / "raw",
                )
            )
        if fp or commit:
            jobs_store.set_scan_identity(job["id"], fingerprint=fp, git_commit=commit)
        report.provenance = {
            k: v
            for k, v in {
                "origin": "discovery",
                "source_id": source.get("id"),
                "source": source.get("name") or source.get("location"),
                "git_commit": commit,
                "fingerprint": fp,
                "source_path": str(target),
            }.items()
            if v is not None
        }
        log_excerpt = _tool_errors(report)

        prog.start("report")
        jobs_store.update_progress(job["id"], stage="persist", steps=prog.snapshot())
        # Write & retain all report formats on disk (like ad-hoc jobs) so every
        # periodic scan has reports/job-<id>/ too - not just the ASPM DB rows.
        write_report(report, report_dir)
        write_triage(report, report_dir)
        duration = time.monotonic() - started
        result = store.persist_success(
            job, report, report_dir=str(report_dir), duration=duration
        )
        prog.finish("report")
        jobs_store.update_progress(job["id"], completion=100, steps=prog.snapshot())
        log.info(
            "Job %s done: result %s, %d finding(s) in %.1fs",
            job["id"],
            result["id"],
            report.to_dict()["summary"]["deduplicated_findings"],
            duration,
        )
    except Exception as exc:  # noqa: BLE001 - convert to a tracked failure
        duration = time.monotonic() - started
        prog.fail_running(detail=f"{type(exc).__name__}: {exc}")
        jobs_store.update_progress(job["id"], steps=prog.snapshot())
        new_status = store.fail_job(
            job,
            error=f"{type(exc).__name__}: {exc}",
            log=log_excerpt or None,
            duration=duration,
        )
        log.warning(
            "Job %s failed (attempt %s/%s -> %s): %s",
            job["id"],
            job["attempt"],
            job["max_attempts"],
            new_status,
            exc,
        )
    # The materialized source is retained on purpose (under sources/discovery/) so
    # it can be retrieved later - it is NOT deleted here. A retry overwrites it via
    # the pre-materialize rmtree above.


def _tool_errors(report) -> str:
    lines = [
        f"{t.scanner}: {t.error}"
        for t in report.tools
        if t.status.value == "error" and t.error
    ]
    return "\n".join(lines)[:8000]


def run_loop(worker_id: str | None = None, *, stop: "callable[[], bool] | None" = None) -> None:
    """Drain the queue forever, sleeping ``poll_interval`` when it is empty."""
    wid = worker_id or config.worker_id()
    poll = config.poll_interval_seconds()
    log.info(
        "Kruncher worker %s started (poll=%ss, queues=manual+periodic, manual first).",
        wid, poll,
    )
    while not (stop and stop()):
        try:
            worked = process_one(wid)
        except Exception:  # noqa: BLE001 - keep the loop alive
            log.exception("Unexpected error in worker loop")
            worked = False
        if not worked:
            time.sleep(poll)
