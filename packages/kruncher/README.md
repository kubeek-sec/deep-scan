# deepscan-kruncher

Periodic, change-driven security scanning of everything a set of **connectors**
can see, with a Postgres-backed job queue, retries, a dead-letter siding and
full job tracking. It is the engine the [admin UI](../kruncher-admin) reports on.

```
 connectors            scheduler (cheap)                worker (expensive)
 ─────────────         ──────────────────               ───────────────────
 github  ─┐            discover scopes  ─┐               claim job (SKIP LOCKED)
 gitlab  ─┼─ sources → probe revisions  ─┼─ scan_jobs →  materialize (clone/copy)
 directory┘            enqueue if changed │   (queue)     run deepscan-core scan
                       reap dead workers  ┘               persist result+findings
                                   └─────────── PostgreSQL ───────────┘
```

## Why Postgres is the queue (no Redis)

Claiming work and writing results are the same concern here, so they live in one
store. Workers claim with `SELECT … FOR UPDATE SKIP LOCKED`, so any number of
krunchers share one queue with no broker and no double-processing; a scan's
result, findings, terminal job state and source bookkeeping are written in **one
transaction**. That directly answers the concurrency between workers, the queue
and the DB writes - adding Redis would add a moving part and a second source of
truth without solving anything here. The scheduler is made safe to replicate
with a Postgres **advisory lock** (only the lock holder runs a tick).

## Branch / change strategy (simple, cheap, effective)

- Only the **default branch** (`main`/`master`, discovered per source) is
  tracked for now. The job carries a `branch` column, so widening to more
  branches later is additive.
- A scan is enqueued **only when the revision changed**. The probe is
  `git ls-remote` (one round trip, no clone) for git and a `(path, size, mtime)`
  signature for directories - unchanged sources cost ~nothing.

## Jobs, retries, dead-letter

- Up to `max_attempts` (default **3**) with backoff (`30s, 2m, 10m`); the failed
  try is recorded in `job_attempts` with its error log.
- After the last attempt a job goes to the **dead-letter** siding (`status=dead`).
- Enqueuing a new scan for a source **supersedes** that source's previous open
  jobs (`queued`/`failed`/`dead`) - the siding self-cleans as fresh scans land.
- Dead/failed jobs can be **relaunched** (CLI `job relaunch`, or the admin UI).
- A crashed worker's `running` job is **reaped** once its heartbeat goes stale
  (`DEEPSCAN_KRUNCHER_LEASE_SECONDS`).

## CLI

```bash
deepscan-kruncher db init                     # apply schema (idempotent)
deepscan-kruncher scope add acme github \
    --config '{"org":"acme","token_env":"GITHUB_TOKEN"}' --families sast --families secret
deepscan-kruncher scope discover acme         # one-off discovery
deepscan-kruncher tick                        # one scheduler iteration
deepscan-kruncher worker                      # drain the queue (run N of these)
deepscan-kruncher run                         # worker + embedded scheduler (all-in-one)
deepscan-kruncher run-one                     # process exactly one job, then exit
deepscan-kruncher jobs --status dead          # inspect the dead-letter siding
deepscan-kruncher job relaunch 42
deepscan-kruncher status
```

`run-one` exists for the **ephemeral-runner** isolation pattern: a one-shot K8s
Job per scan (see [deploy/](../../deploy)).

## Configuration (env, `.env` fallback)

| Var | Default | Meaning |
|---|---|---|
| `DEEPSCAN_DB_DSN` | - | Full Postgres URL (wins over the parts below) |
| `DEEPSCAN_DB_HOST/PORT/NAME/USER/PASSWORD` | `localhost/5432/deepscan/deepscan/` | DSN parts |
| `DEEPSCAN_KRUNCHER_ID` | `host:pid` | `locked_by` identity |
| `DEEPSCAN_KRUNCHER_WORK_DIR` | `~/.local/share/kubeek-sec/deepscan` | scratch for clones |
| `DEEPSCAN_KRUNCHER_POLL_INTERVAL` | `5` | idle poll seconds |
| `DEEPSCAN_KRUNCHER_SCHEDULER_INTERVAL` | `60` | scheduler tick seconds |
| `DEEPSCAN_KRUNCHER_MAX_ATTEMPTS` | `3` | retry ceiling |
| `DEEPSCAN_KRUNCHER_LEASE_SECONDS` | `1800` | stale-running reap threshold |
| `DEEPSCAN_TRIVY_SERVER` | - | Trivy server URL; SCA scans in client mode (no DB download) |

Tokens are read from the `token_env` named in each scope's config and are never
written to the database.
