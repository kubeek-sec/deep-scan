# deepscan-jobs

Shared, Postgres-backed **scan job** store and runner. One queue, one schema,
reused by every front-end that needs to turn a target into a scan:

- **API** (`deepscan-api`) - on-demand submissions (url / git / path / zip
  upload) drained by an in-process worker pool.
- **MCP server** (`deepscan-mcp`) - agent/IDE scans; runs the job inline and
  surfaces the report (the job still lands in the shared store / dashboard).
- **kruncher** (`deepscan-kruncher`) - discovery-driven, change-detected scans
  of connector sources (scopes/sources/revisions/ASPM live here too).

Postgres is the broker: workers claim with `SELECT ... FOR UPDATE SKIP LOCKED`,
the scheduler serializes with an advisory lock. Jobs carry an `origin`
(`discovery` for kruncher, `adhoc` for API/MCP) so each worker only claims what
it can run.

```python
from deepscan_jobs import db, store, worker
db.init_schema()
job = store.create_adhoc_job(target_type="path", target="/code", surface="api")
```

Config (env, `.env` fallback via `deepscan_core.config`): `DEEPSCAN_DB_DSN` (or
`DEEPSCAN_DB_HOST/PORT/NAME/USER/PASSWORD`), `DEEPSCAN_DATA_DIR` (targets /
reports / uploads), `DEEPSCAN_DB_POOL`, `DEEPSCAN_LEASE_SECONDS`,
`DEEPSCAN_MAX_ATTEMPTS`.
