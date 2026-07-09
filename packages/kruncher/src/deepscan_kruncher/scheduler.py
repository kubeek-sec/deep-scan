"""The scheduler: the cheap, periodic half of the system.

Each tick (guarded by a Postgres advisory lock so only one replica acts):

1. **Discover** scopes whose refresh interval elapsed.
2. **Probe** each due source's current revision - ``git ls-remote`` for git,
   a content signature for directories - *without* cloning or reading files.
3. **Enqueue** a scan only when the revision differs from the last *scanned*
   one (and no equivalent job is already open), so unchanged sources cost one
   network round-trip and nothing else.
4. **Reap** jobs whose worker died mid-scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from . import db, discovery, store
from .connectors import get as get_connector
from deepscan_input_connector_base import ConnectorError

log = logging.getLogger("deepscan.kruncher.scheduler")


@dataclass
class TickReport:
    scopes_discovered: int = 0
    sources_checked: int = 0
    scans_enqueued: int = 0
    jobs_reaped: int = 0
    skipped_no_lock: bool = False


def _has_open_job(source_id: int, revision: str | None) -> bool:
    row = db.fetchone(
        "SELECT 1 FROM scan_jobs WHERE source_id = %s AND status IN ('queued','running') "
        "AND target_revision IS NOT DISTINCT FROM %s LIMIT 1",
        (source_id, revision),
    )
    return row is not None


def run_discovery_due() -> int:
    count = 0
    for scope in store.scopes_due_for_discovery():
        discovery.refresh_scope(scope)
        count += 1
    return count


def run_change_detection(limit: int = 200) -> tuple[int, int]:
    """Probe due sources; enqueue scans for changed ones. Returns (checked, enqueued)."""
    checked = enqueued = 0
    for source in store.sources_due_for_check(limit):
        checked += 1
        connector = get_connector(source["connector"])
        scope_config = source["scope_config"]
        try:
            revision = connector.current_revision(_as_discovered(source), scope_config)
        except ConnectorError as exc:
            log.warning("Revision probe failed for %s: %s", source["name"], exc)
            store.mark_source_checked(source["id"], None)
            continue
        store.mark_source_checked(source["id"], revision)

        unchanged = (
            revision is not None and revision == source["last_scanned_revision"]
        )
        never_scanned = source["last_scanned_revision"] is None
        if unchanged:
            continue
        if revision is None and not never_scanned:
            continue  # can't determine a new revision; nothing actionable
        if _has_open_job(source["id"], revision):
            continue
        store.enqueue_scan(
            source["id"], target_revision=revision, branch=source["default_branch"]
        )
        enqueued += 1
        log.info("Enqueued scan for %s @ %s", source["name"], (revision or "HEAD")[:12])
    return checked, enqueued


def _as_discovered(source_row: dict):
    """Adapt a source DB row to the DiscoveredSource shape connectors expect."""
    from deepscan_input_connector_base import DiscoveredSource

    return DiscoveredSource(
        external_id=source_row["external_id"],
        kind=source_row["kind"],
        name=source_row["name"],
        location=source_row["location"],
        default_branch=source_row["default_branch"],
        metadata=source_row["metadata"] or {},
    )


def tick() -> TickReport:
    """One scheduler iteration, serialized across replicas by an advisory lock."""
    report = TickReport()
    with db.connection() as lock_conn:
        with db.advisory_lock(lock_conn) as acquired:
            if not acquired:
                report.skipped_no_lock = True
                return report
            report.scopes_discovered = run_discovery_due()
            report.sources_checked, report.scans_enqueued = run_change_detection()
            report.jobs_reaped = store.reap_stale_jobs()
    return report
