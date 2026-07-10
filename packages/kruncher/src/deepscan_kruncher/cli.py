"""``deepscan-kruncher`` command line.

    deepscan-kruncher db init|check|dump-schema
    deepscan-kruncher scope add NAME CONNECTOR --config '{"org":"acme"}' [...]
    deepscan-kruncher scope list|show NAME|rm NAME|enable NAME|disable NAME
    deepscan-kruncher scope discover NAME
    deepscan-kruncher sources [--scope NAME]
    deepscan-kruncher tick                 # one scheduler iteration
    deepscan-kruncher scheduler            # scheduler loop
    deepscan-kruncher worker               # worker loop
    deepscan-kruncher run-one              # process exactly one job (ephemeral)
    deepscan-kruncher run                  # worker + embedded scheduler
    deepscan-kruncher jobs [--status ...] | job show ID | job relaunch ID
    deepscan-kruncher status
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import threading
import time
from pathlib import Path

from . import config, db, dispatcher, discovery, scheduler, store, worker
from .connectors import available

_OK, _ERR = 0, 2


def _load_config(args) -> dict:
    if args.config_file:
        return json.loads(Path(args.config_file).read_text(encoding="utf-8"))
    if args.config:
        return json.loads(args.config)
    return {}


# --------------------------------------------------------------------------- #
# command handlers
# --------------------------------------------------------------------------- #


def _cmd_db(args) -> int:
    if args.db_command == "init":
        db.init_schema()
        print("Schema applied.")
        return _OK
    if args.db_command == "check":
        db.ping()
        print(f"Connected: {config.database_dsn().split('@')[-1]}")
        return _OK
    if args.db_command == "dump-schema":
        print(db.schema_sql())
        return _OK
    return _ERR


def _cmd_scope(args) -> int:
    if args.scope_command == "add":
        scope = store.upsert_scope(
            name=args.name,
            connector=args.connector,
            scope_config=_load_config(args),
            enabled=not args.disabled,
            refresh_interval_seconds=args.refresh,
            rescan_interval_seconds=args.rescan,
            families=args.families.split(",") if args.families else None,
        )
        print(f"Scope {scope['name']!r} (id={scope['id']}, connector={scope['connector']}).")
        return _OK
    if args.scope_command == "list":
        for s in store.list_scopes():
            flag = "on " if s["enabled"] else "off"
            print(f" [{flag}] {s['id']:>3}  {s['name']:<24} {s['connector']:<10} {s['config']}")
        return _OK
    if args.scope_command == "show":
        s = store.get_scope_by_name(args.name)
        if not s:
            print(f"No scope named {args.name!r}.", file=sys.stderr)
            return _ERR
        print(json.dumps(s, indent=2, default=str))
        srcs = store.list_sources(s["id"])
        print(f"\n{len(srcs)} active source(s):")
        for src in srcs[:50]:
            print(f"  {src['id']:>5} {src['kind']:<9} {src['name']}")
        return _OK
    if args.scope_command in ("enable", "disable"):
        s = store.get_scope_by_name(args.name)
        if not s:
            print(f"No scope named {args.name!r}.", file=sys.stderr)
            return _ERR
        store.set_scope_enabled(s["id"], args.scope_command == "enable")
        print(f"Scope {args.name!r} {args.scope_command}d.")
        return _OK
    if args.scope_command == "rm":
        s = store.get_scope_by_name(args.name)
        if not s:
            print(f"No scope named {args.name!r}.", file=sys.stderr)
            return _ERR
        store.delete_scope(s["id"])
        print(f"Scope {args.name!r} deleted.")
        return _OK
    if args.scope_command == "discover":
        outcome = discovery.refresh_scope_by_name(args.name)
        if outcome.error:
            print(f"Discovery error: {outcome.error}", file=sys.stderr)
            return _ERR
        print(
            f"Discovered {outcome.discovered} source(s), "
            f"deactivated {outcome.deactivated}."
        )
        return _OK
    return _ERR


def _cmd_sources(args) -> int:
    scope_id = None
    if args.scope:
        s = store.get_scope_by_name(args.scope)
        if not s:
            print(f"No scope named {args.scope!r}.", file=sys.stderr)
            return _ERR
        scope_id = s["id"]
    for src in store.list_sources(scope_id):
        rev = (src["last_scanned_revision"] or "-")[:12]
        print(f" {src['id']:>5} {src['kind']:<9} {rev:<12} {src['name']}")
    return _OK


def _cmd_tick(args) -> int:
    report = scheduler.tick()
    if report.skipped_no_lock:
        print("Another scheduler holds the lock; skipped.")
        return _OK
    print(
        f"discovered={report.scopes_discovered} checked={report.sources_checked} "
        f"enqueued={report.scans_enqueued} reaped={report.jobs_reaped}"
    )
    return _OK


def _cmd_scheduler(args) -> int:
    interval = config.scheduler_interval_seconds()
    logging.info("Scheduler loop started (interval=%ss).", interval)
    while True:
        try:
            scheduler.tick()
        except Exception:  # noqa: BLE001
            logging.exception("Scheduler tick failed")
        time.sleep(interval)


def _cmd_worker(args) -> int:
    worker.run_loop()
    return _OK


def _cmd_run_one(args) -> int:
    did = worker.process_one()
    print("Processed one job." if did else "No job available.")
    return _OK if did else 3


def _cmd_materialize(args) -> int:
    """Stage 1 of the split sandbox pod: materialize a claimed job's source."""
    from deepscan_jobs import store as jobs_store
    from deepscan_jobs.worker import materialize_job

    job = jobs_store.get_job(args.job_id)
    if job is None:
        print(f"No such job: {args.job_id}", file=sys.stderr)
        return _ERR
    path = asyncio.run(materialize_job(
        job, args.dest,
        allow_private=config.allow_private_targets(),
        allow_local_paths=config.allow_local_paths(),
    ))
    print(f"Materialized job {args.job_id} -> {path}")
    return _OK


def _cmd_scan_only(args) -> int:
    """Stage 3 of the split sandbox pod: scan a materialized dir and persist."""
    from deepscan_jobs import store as jobs_store
    from deepscan_jobs.worker import scan_and_persist_job

    job = jobs_store.get_job(args.job_id)
    if job is None:
        print(f"No such job: {args.job_id}", file=sys.stderr)
        return _ERR
    asyncio.run(scan_and_persist_job(
        job, args.src, allow_private=config.allow_private_targets(),
    ))
    print(f"Scanned + persisted job {args.job_id}")
    return _OK


def _cmd_prune(args) -> int:
    from deepscan_jobs import retention

    targets = tuple(t.strip() for t in args.targets.split(",") if t.strip())
    max_age = args.max_age_days
    # A safe default so a bare `prune` (e.g. the CronJob) still does something
    # sensible instead of nothing: keep 30 days unless any criterion is given.
    if max_age is None and args.max_size_gb is None and args.min_free_gb is None:
        max_age = 30.0
    res = retention.prune(
        max_age_days=max_age, max_size_gb=args.max_size_gb,
        min_free_gb=args.min_free_gb, targets=targets, dry_run=args.dry_run,
    )
    verb = "would delete" if res.dry_run else "deleted"
    for p in res.deleted_paths:
        print(f"  {verb}: {p}")
    print(f"prune: {res.scanned} dir(s) scanned, {res.protected} protected (active), "
          f"{verb} {res.deleted} ({res.freed_gib:.2f} GiB).")
    return _OK


def _cmd_dispatch(args) -> int:
    dispatcher.run_loop()
    return _OK


def _cmd_dispatch_one(args) -> int:
    did = dispatcher.dispatch_one()
    print("Dispatched one job." if did else "No job available.")
    return _OK if did else 3


def _cmd_run(args) -> int:
    """Single process: a worker loop plus an embedded scheduler thread."""
    interval = config.scheduler_interval_seconds()

    def _sched() -> None:
        while True:
            try:
                scheduler.tick()
            except Exception:  # noqa: BLE001
                logging.exception("Embedded scheduler tick failed")
            time.sleep(interval)

    threading.Thread(target=_sched, name="kruncher-scheduler", daemon=True).start()
    worker.run_loop()
    return _OK


_QUEUE_LABEL = {"adhoc": "manual", "discovery": "periodic"}


def _cmd_jobs(args) -> int:
    for j in store.list_jobs(status=args.status, origin=args.origin, limit=args.limit):
        queue = _QUEUE_LABEL.get(j["origin"], j["origin"] or "?")
        # periodic jobs name a source + revision; manual jobs name an ad-hoc target.
        subject = j["source_name"] or j.get("target") or "-"
        rev = (j["target_revision"] or "-")[:12]
        print(
            f" {j['id']:>6} {queue:<8} {j['status']:<10} a{j['attempt']}/{j['max_attempts']} "
            f"{j['completion']:>3}% {rev:<12} {subject}"
        )
    return _OK


def _cmd_job(args) -> int:
    if args.job_command == "show":
        j = store.get_job(args.id)
        if not j:
            print(f"No job {args.id}.", file=sys.stderr)
            return _ERR
        print(json.dumps(j, indent=2, default=str))
        print("\nattempts:")
        for a in store.get_job_attempts(args.id):
            print(f"  #{a['attempt']} {a['status']}: {a['error'] or ''}")
        return _OK
    if args.job_command == "relaunch":
        row = store.relaunch_job(args.id)
        if not row:
            print(f"Job {args.id} not relaunchable.", file=sys.stderr)
            return _ERR
        print(f"Job {args.id} re-queued.")
        return _OK
    if args.job_command == "cancel":
        store.cancel_job(args.id)
        print(f"Job {args.id} cancelled (if it was queued/failed).")
        return _OK
    return _ERR


def _cmd_status(args) -> int:
    by_origin = store.queue_depth_by_origin()
    print("connectors:", ", ".join(available()))
    for origin in ("adhoc", "discovery"):
        label = _QUEUE_LABEL.get(origin, origin)
        depth = by_origin.get(origin, {})
        body = ", ".join(f"{k}={v}" for k, v in sorted(depth.items())) or "(empty)"
        print(f"{label} queue:", body)
    print("scopes:", len(store.list_scopes()))
    return _OK


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="deepscan-kruncher", description="Deep Scan kruncher")
    sub = p.add_subparsers(dest="command", required=True)

    db_p = sub.add_parser("db", help="Database setup.")
    db_sub = db_p.add_subparsers(dest="db_command", required=True)
    for name in ("init", "check", "dump-schema"):
        db_sub.add_parser(name)

    sc = sub.add_parser("scope", help="Manage scopes.")
    sc_sub = sc.add_subparsers(dest="scope_command", required=True)
    add = sc_sub.add_parser("add", help="Create or update a scope.")
    add.add_argument("name")
    add.add_argument("connector", choices=available())
    add.add_argument("--config", help="Inline JSON connector config.")
    add.add_argument("--config-file", help="Path to a JSON connector config.")
    add.add_argument("--families", help="Comma-separated scanner families to limit to.")
    add.add_argument("--refresh", type=int, default=3600, help="Discovery interval (s).")
    add.add_argument("--rescan", type=int, default=86400, help="Change-probe interval (s).")
    add.add_argument("--disabled", action="store_true", help="Create it disabled.")
    sc_sub.add_parser("list")
    for name in ("show", "rm", "enable", "disable", "discover"):
        sp = sc_sub.add_parser(name)
        sp.add_argument("name")

    src = sub.add_parser("sources", help="List sources.")
    src.add_argument("--scope", help="Limit to one scope by name.")

    sub.add_parser("tick", help="Run one scheduler iteration.")
    sub.add_parser("scheduler", help="Run the scheduler loop.")
    sub.add_parser("worker", help="Run the worker loop.")
    sub.add_parser("run-one", help="Process exactly one job, then exit (ephemeral).")
    sub.add_parser("run", help="Worker loop + embedded scheduler in one process.")

    # Split-pod stages (the 3-stage sandbox pod: materialize -> resolve -> scan).
    # The job must already be claimed by a dispatcher; these do one stage each.
    mat = sub.add_parser(
        "materialize", help="Stage 1: fetch a claimed job's source into a dir (no scan)."
    )
    mat.add_argument("job_id", type=int)
    mat.add_argument("dest", help="Directory to materialize the source into (shared volume).")
    so = sub.add_parser(
        "scan-only", help="Stage 3: scan an already-materialized dir and persist the report."
    )
    so.add_argument("job_id", type=int)
    so.add_argument("src", help="Directory holding the materialized (and resolved) source.")

    sub.add_parser(
        "dispatch", help="Claim jobs and run each through the isolated 3-stage flow (loop)."
    )
    sub.add_parser(
        "dispatch-one", help="Dispatch exactly one job through the isolated stages, then exit."
    )

    pr = sub.add_parser(
        "prune", help="Delete old retained sources/reports/uploads (by age, size cap, free space)."
    )
    pr.add_argument("--max-age-days", type=float, help="Delete job dirs older than N days.")
    pr.add_argument("--max-size-gb", type=float, help="Cap total data size; evict oldest until under.")
    pr.add_argument("--min-free-gb", type=float, help="Ensure at least F GiB free; evict oldest until met.")
    pr.add_argument("--targets", default="reports,sources,uploads",
                    help="Comma-separated subtrees to sweep (default: all).")
    pr.add_argument("--dry-run", action="store_true", help="Show what would be deleted, delete nothing.")

    jobs = sub.add_parser("jobs", help="List jobs (both queues by default).")
    jobs.add_argument("--status", help="Filter by status.")
    jobs.add_argument(
        "--origin",
        choices=("adhoc", "discovery"),
        help="Filter by queue: 'adhoc' (manual API/MCP) or 'discovery' (periodic).",
    )
    jobs.add_argument("--limit", type=int, default=50)

    job = sub.add_parser("job", help="Inspect/act on a job.")
    job_sub = job.add_subparsers(dest="job_command", required=True)
    for name in ("show", "relaunch", "cancel"):
        sp = job_sub.add_parser(name)
        sp.add_argument("id", type=int)

    sub.add_parser("status", help="Queue and scope overview.")
    return p


_HANDLERS = {
    "db": _cmd_db,
    "scope": _cmd_scope,
    "sources": _cmd_sources,
    "tick": _cmd_tick,
    "scheduler": _cmd_scheduler,
    "worker": _cmd_worker,
    "run-one": _cmd_run_one,
    "run": _cmd_run,
    "materialize": _cmd_materialize,
    "scan-only": _cmd_scan_only,
    "dispatch": _cmd_dispatch,
    "dispatch-one": _cmd_dispatch_one,
    "prune": _cmd_prune,
    "jobs": _cmd_jobs,
    "job": _cmd_job,
    "status": _cmd_status,
}


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    args = _build_parser().parse_args(argv)
    handler = _HANDLERS[args.command]
    try:
        code = handler(args)
    except KeyboardInterrupt:
        code = _OK
    finally:
        db.close_pool()
    if argv is None:
        sys.exit(code)
    return code


if __name__ == "__main__":
    main()
