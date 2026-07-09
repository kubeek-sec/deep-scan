# deepscan-kruncher-admin

A no-build web UI and small REST API over the [kruncher](../kruncher) store:
an **ASPM** (Application Security Posture Management) dashboard plus job
tracking and re-launch. It holds no state of its own - every read goes straight
to Postgres.

```bash
deepscan-kruncher-admin            # serves http://127.0.0.1:8900
```

## What it shows

- **Dashboard** - current posture from the latest scan per source: KPI cards
  (sources scanned, at-risk, critical/high/medium counts), a **trend** chart
  over the last **3 months** (weekly) or **12 months** (monthly), a **by-scope**
  breakdown and the **most exposed sources**. Trends consolidate history by
  taking the latest result per source per bucket, so re-scans don't inflate the
  numbers.
- **Sources** - searchable, scope-filterable, risk-filterable and **paginated**
  list (built for a very large number of projects), with a per-source drawer of
  latest findings and scan history.
- **Jobs** - filter by status (incl. the `dead` siding), watch progress, open
  the attempt log, and **relaunch** or **cancel** with one click.
- **Scopes** - create / edit / delete scopes from the UI (connector picker with
  a prefilled example config, families, intervals, enable/disable), and trigger
  discovery on demand.
- **Sources** - add a source manually, edit it, **scan now**, deactivate /
  reactivate, or delete; inactive sources are shown with a badge.

## API (under `/api`)

| Endpoint | Purpose |
|---|---|
| `GET /overview` | queue depth + posture totals + scope inventory |
| `GET /posture` | totals, by-scope breakdown, top exposed sources |
| `GET /trends?window=3m\|1y` | consolidated severity time series |
| `GET /sources?scope_id=&q=&risk=&limit=&offset=` | paginated source list |
| `GET /sources/{id}` | source detail: findings, history, jobs |
| `GET /jobs?status=&source_id=` · `GET /jobs/{id}` | job list / detail+attempts |
| `POST /jobs/{id}/relaunch` · `/cancel` | job control |
| `GET /connectors` | available connectors + example configs (for the forms) |
| `POST /scopes` · `PUT /scopes/{id}` · `DELETE /scopes/{id}` | scope CRUD |
| `POST /scopes/{id}/enabled?enabled=` · `/discover` | toggle / discover a scope |
| `POST /sources` · `PUT /sources/{id}` · `DELETE /sources/{id}` | source CRUD |
| `POST /sources/{id}/active?active=` · `/scan` | toggle / scan a source now |

Configure with `DEEPSCAN_ADMIN_HOST` / `DEEPSCAN_ADMIN_PORT` and the same
`DEEPSCAN_DB_*` variables as the kruncher.
