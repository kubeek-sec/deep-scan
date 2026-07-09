# Architecture

One scanner engine, one report formalism, exposed several ways. Everything
shares the same scanners, the same normalized `Finding` model, the same
`(location, message)` deduplication, and the same four report formats (JSON,
Markdown, HTML, SARIF 2.1.0).

```
                      ┌──────────────────────────────┐
                      │      deepscan-core            │
                      │  registry · secure install ·  │
                      │  scanners · dedup · reporting │
                      └──────────────────────────────┘
                         ▲          ▲           ▲
            ┌────────────┘          │           └────────────┐
   ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
   │  deepscan-mcp   │   │   deepscan-cli   │   │     deepscan-api     │
   │  agents / IDE   │   │  local & CI/CD   │   │  job queue + web app │
   └─────────────────┘   └──────────────────┘   └──────────────────────┘
```

## Monorepo layout

| Path | What it is |
|---|---|
| `packages/core` | `deepscan-core` - scanner registry, secure tool installer, SARIF parsing, dedup, report rendering, the `analysis`/`ai-analysis` engines |
| `packages/graphoofy` | `deepscan-graphoofy` - AST + code-graph pipeline from graphoofy (code-only, no AI/documents): tree-sitter extraction → NetworkX graph |
| `packages/mcp-server` | `deepscan-mcp` - FastMCP server exposing the scanners to agents/IDEs |
| `packages/cli` | `deepscan-cli` - the `deepscan` command for local runs and CI gates |
| `packages/jobs` | `deepscan-jobs` - shared Postgres-backed scan-job store + runner reused by the API, MCP server and kruncher |
| `packages/api` | `deepscan-api` - FastAPI REST service over the shared job queue; serves the web app |
| `packages/web` | `deepscan-web` - static frontend (no build step) served by the API |
| `packages/connectors/base` | connector contract + registry + shared git/dir helpers (`deepscan-input-connector-base`) |
| `packages/connectors/git` | `deepscan-input-connector-git` - scan a repo by direct URL (no org, token optional) |
| `packages/connectors/github` | `deepscan-input-connector-github` - discover repos under an org/user |
| `packages/connectors/gitlab` | `deepscan-input-connector-gitlab` - discover projects under a group/user |
| `packages/connectors/directory` | `deepscan-input-connector-directory` - wrap a server-local directory |
| `packages/kruncher` | `deepscan-kruncher` - change-driven scanning engine + Postgres job queue + CLI |
| `packages/kruncher-admin` | `deepscan-kruncher-admin` - ASPM dashboard + job control UI/API |
| `deploy/` | Dockerfile, docker-compose (horizontal scaling), Kustomize (K8s) |
| `db/` | schema + ops scripts: `init`/`reset`/`create-tables`/`set-scope`/`report` |
| `tests/` | pytest suite (connectors, schema parity, Postgres queue integration) |
| `guinea-pig/` | deliberately-vulnerable test project + a `security-triage` skill and `/security-eval` command |
| `inspiration/` | prior projects this design draws on (not part of the build) |

It is a [uv](https://docs.astral.sh/uv/) workspace (Python 3.13). Install once:

```bash
uv sync
uv run deepscan tools install all   # downloads pinned, checksum-verified tools
```

## Two-phase analysis model

Two scanners work as a pair on top of the rest: `analysis` finds the *risk
zones* deterministically, then `ai-analysis` assesses the *real risk* of
everything found and prioritizes it for a human. They run in **two phases** -
all the producer scanners (SAST/SCA/secret/IaC/DAST/`analysis`) run first, then
`ai-analysis` consumes their combined findings.

See [scanners.md](scanners.md) for the full scanner catalog and the `analysis`
/ `ai-analysis` deep dives.

## Adding a scanner

1. Pin the tool in `packages/core/.../install/catalog.py` (URL + SHA-256 per platform).
2. Add `packages/core/.../scanners/<tool>.py`: subclass `Scanner`, set
   `name`/`family`/`mode`/`tool`, implement `_execute()` returning `Finding`s
   (use `parse_sarif` if the tool emits SARIF).
3. Register the instance in `scanners/__init__.py`.

Every front-end (CLI, MCP, API) picks it up automatically from the registry.

A **consumer** scanner (like `ai-analysis`) sets `consumes_findings = True`: the
runner runs it in a second phase and exposes every producer's findings on
`ctx.prior_findings`. Return a `ScanOutput(findings, payload=...)` from
`_execute` to attach structured output (the `payload` is surfaced on
`Report.triage`).

## Security model

- **Tool installation** is pinned by exact version and **SHA-256 verified**
  before extraction; archives are extracted member-by-member (no zip-slip);
  installs are atomic. Downloads are HTTPS-only with a size cap.
- **Scan targets** are canonicalized before reaching any subprocess (no
  leading-dash argument injection), optionally confined to `DEEPSCAN_SCAN_ROOT`;
  git clones disable credential prompts; zip extraction blocks traversal,
  symlinks and bombs.
- **Subprocesses** run with `shell=False` and hard timeouts; a scanner never
  raises - it reports `ok`, `skipped`, or `error`.
- **Secrets** are reported with redacted values and never committed.
- The REST API can reject private/loopback DAST targets
  (`DEEPSCAN_ALLOW_PRIVATE_TARGETS=false`) to avoid being an SSRF proxy.

For scan isolation in untrusted infrastructure (ephemeral runners, network
fences, hardened pods), see [deployment.md](deployment.md#scan-isolation).

## Telemetry (anonymous, opt-in via Sentry)

Set `SENTRY_DSN` (env or the project `.env`) to push **anonymous** operational
and product metrics through the Sentry SDK. It is **off unless a DSN is set**,
and can be force-disabled with `DEEPSCAN_TELEMETRY=false`. Coverage is automatic
across **every surface** - CLI, MCP, REST API and the kruncher fleet - because
they all run through `run_scan`, which emits one `deepscan.scan` transaction per
scan ([`deepscan_core/metrics.py`](../packages/core/src/deepscan_core/metrics.py)).

Each transaction carries low-cardinality **tags** (`mode`, `surface`,
`had_findings`, deepscan version, os/arch, and a random non-identifying install
id) and numeric **span attributes**: total/deduplicated finding counts, counts
per **family** and per **severity**, scan duration, and scanners ran/skipped/
errored - enough to answer "how often is it used", "what kinds of issues are
detected", "how much did it help" and "how long do scans take" without any
persistence. **Privacy by construction:** `send_default_pii=False`, and it never
sends the scan target path, file names, finding locations/messages or any secret
value - only the aggregates above. Knobs: `SENTRY_ENVIRONMENT`,
`SENTRY_TRACES_SAMPLE_RATE` (default 1.0; lower it for a large fleet). Telemetry
failures are swallowed - they never affect a scan.
