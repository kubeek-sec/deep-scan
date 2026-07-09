# Interfaces - CLI, MCP, REST API

The same engine is exposed three ways. All of them share the scanner registry,
the normalized `Finding` model, dedup and the four report formats.

## CLI

```bash
# Auto-detect mode (directory → static, URL → dynamic):
uv run deepscan scan ./my-project
uv run deepscan scan http://127.0.0.1:3000

# Filter by family or single scanner; choose report formats:
uv run deepscan scan ./my-project --family sast --family secret --format sarif

# CI gate: exit 1 if anything is at/above HIGH:
uv run deepscan scan ./my-project --fail-on high

# Introspection:
uv run deepscan scanners
uv run deepscan tools status
```

Reports are written to `reports/scan_<timestamp>_<mode>/report.{json,md,html,sarif}`
(plus `triage.{json,md,html}` when ai-analysis ran). The HTML report and triage
share the web dashboard's look - dark theme, the ◈ Deep Scan brand and the same
severity palette - via a single shared theme
([`reporting/theme.py`](../packages/core/src/deepscan_core/reporting/theme.py)).

### Logging / progress

Scans log progress to **stderr** under the `deepscan.*` loggers - at **INFO** by
default you see the scan starting, each scanner starting and finishing (status,
duration, finding count), the two-phase transition and the final summary. This
is especially useful for the long-running `ai-analysis` (it logs invoking the
model, the response size and how many triage items were parsed).

```bash
# INFO is on by default. Turn on DEBUG (per-scanner internals, subprocess
# commands, graph stats, prompt size) with an env var or the --debug flag:
DEEPSCAN_DEBUG=1 uv run deepscan scan ./my-project --scanner ai-analysis
uv run deepscan scan ./my-project --debug
# Or set a specific level (DEBUG/INFO/WARNING/ERROR):
DEEPSCAN_LOG_LEVEL=WARNING uv run deepscan scan ./my-project
```

The same logging is initialized by the MCP server and the API. `--quiet` only
suppresses the human summary block, not the logs (lower the level for that).

## MCP server

```bash
# stdio (for an IDE/agent that launches the process):
uv run deepscan-mcp

# streamable HTTP on http://127.0.0.1:8000/mcp:
uv run deepscan-mcp --transport streamable-http
```

> **Client URL must be `…/mcp` with no trailing slash.** The endpoint is served
> at exactly `/mcp`; a trailing `/mcp/` triggers a 307 redirect that MCP clients
> (including Claude) don't follow cleanly across the POST/SSE handshake, so the
> connection fails. In Docker the server binds `0.0.0.0:8000` (set
> `FASTMCP_HOST`); clients on the host connect via the mapped port,
> e.g. `http://localhost:8000/mcp`.

Tools: `static_scan`, `dynamic_scan`, `scan_family`, `scan_with`,
`list_scanners`, `tool_status`, `install_tool`, and - to interrogate a project's
analysis code graph - `list_graph_questions` and `query_graph(project_dir,
question, target?, limit?)`. The latter answers precise AppSec questions
(unsanitized sources, critical functions, endpoints → sink/taint, shortest/all
paths to critical, external deps, vulnerable-deps → critical, attack paths,
blast radius) by returning resolved nodes/paths with `label` + `location`; the
graph is built on first call and cached. Wire it into a project with an
`.mcp.json` (see `guinea-pig/.mcp.json`).

Every scan becomes a job in the **shared Postgres store** (`deepscan-jobs`, the
same **manual queue** the API submits to) - so MCP scans also show up in the API
dashboard. By default the deployed http server hands the job to the **kruncher
worker fleet** and polls for the result (reading the report off the shared
volume); local stdio runs it inline (an IDE-launched server has no fleet).
Override with `DEEPSCAN_MCP_RUN_VIA_KRUNCHER=true|false`. `scan_with` returns
just that scanner's report; `scan_family`/`static_scan`/`dynamic_scan` also
append the **code-graph report** (`graph.json`, when the `analysis` scanner ran).

**How the project reaches the server depends on the transport:**

- **stdio** (server launched locally by the IDE/agent) - pass `project_dir`, just
  the path; the server reads it off the local filesystem. No upload.
- **streamable-http** (server possibly remote) - upload the project first, then
  pass the returned `upload_id`:

  ```python
  from deepscan_mcp.client import upload_project
  upload_id = upload_project("./my-project", base_url="http://host:8000")
  # then call the tool: static_scan(upload_id=upload_id)
  ```

  A server-side `project_dir` is refused over http unless
  `DEEPSCAN_MCP_ALLOW_LOCAL_PATHS=1` is set on the server.

The MCP server needs the Postgres DSN (`DEEPSCAN_DB_DSN` or `DEEPSCAN_DB_*`) and
shares `DEEPSCAN_DATA_DIR` (reports/uploads) with the API.

## REST API + web app

```bash
uv run deepscan-api            # serves http://127.0.0.1:8800
```

The API is a **submitter, not an executor**: a scan posted here becomes a queued
job on the **manual queue** (`deepscan-jobs`, `origin='adhoc'`) and the **kruncher
worker fleet** runs it - the same fleet that runs periodic scans, so the API
process is never saturated by scanning. Manual jobs are drained **ahead of**
periodic ones. Submit a directory, a git URL, a zip upload, or (when enabled) a
local path; poll the job; fetch the report in any format. Open
`http://127.0.0.1:8800/` for the dashboard - a **New scan** tab to launch and
follow the scan you just started, a **History** tab listing every past scan,
**paginated 50 per page**, and a **CI templates** tab (see below). Scans
submitted here and via the MCP server both appear, tagged with their queue.
(Running the API therefore requires a reachable kruncher worker; `docker compose
up` starts the fleet.)

The **CI templates** tab is a five-step wizard - pick a platform (GitHub Actions,
Gitea Actions, GitLab CI, Bitbucket, Azure Pipelines, Jenkins, TeamCity), choose
what to scan and the tools per capability, the report formats, the severity gate
and whether to fail or warn - that generates a ready-to-commit pipeline file. The
generated file runs the Deep Scan CLI from this project's Docker image (built from
`deploy/docker/Dockerfile`, pushed to your registry) via `uv run deepscan scan`
with the flags you picked; it can pass CI secrets/variables through and point at
project-specific rules (`DEEPSCAN_CONFIG_DIR`). The capability → tool catalog comes
straight from the live scanner registry, so it never drifts from what the CLI runs.

Key endpoints (all under `/api`): `POST /scans`, `POST /scans/zip`,
`GET /scans` (paginated - `?limit=&offset=`, total in the `X-Total-Count`
header), `GET /scans/{id}`, `GET /scans/{id}/report?format=…`,
`DELETE /scans/{id}`, `GET /scanners`, `GET /tools`,
`GET /pipeline/options`, `POST /pipeline/generate`, `GET /healthz`.

Configuration (env or `.env`): `DEEPSCAN_API_HOST/PORT`,
`DEEPSCAN_API_ALLOW_LOCAL_PATHS`, `DEEPSCAN_ALLOW_PRIVATE_TARGETS`; the job store
is Postgres (`DEEPSCAN_DB_DSN` or `DEEPSCAN_DB_*`) and reports/uploads live under
the shared `DEEPSCAN_DATA_DIR` (mount the same volume across the API, MCP server
**and the kruncher fleet** so each can serve the reports the fleet writes).
