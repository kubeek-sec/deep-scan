---
description: Security evaluation - zip the project, scan it through the Deep Scan MCP (jobs infrastructure), return the report, and group the findings into a prioritized, PR-ready remediation plan.
argument-hint: "[path to scan | 'full'] (default: whole project)"
---

# /security-eval

Evaluate the security of this project and produce a **prioritized remediation
plan, grouped so each group becomes one easy-to-review PR**. The scan runs
server-side on the Deep Scan **jobs infrastructure** (the kruncher fleet); this
session - *local Claude* - does the prioritization and grouping. This command
only evaluates and plans; it changes no code. Run `/security-patch` to implement.

> **External-address policy (whole suite).** Any request that leaves the machine
> - in evaluation, demonstration or a non-regression test - must go to a
> controlled `kubeek.com` canary endpoint and nothing else. See
> [`.claude/canary-endpoints.md`](../canary-endpoints.md) and the
> [`canary.py`](../scripts/canary.py) helper. These endpoints are inert and exist
> only to validate drop/exfiltration/info-collection paths.

## Preconditions
- The Deep Scan stack is up: the MCP at the `url` in `.mcp.json` (default
  `http://127.0.0.1:8000/mcp`), the API at `http://127.0.0.1:8800`, and a
  kruncher worker. Bring it up from the deep-scan repo root with `./start.sh`.
- The `deepscan` MCP tools are deferred - load them first:
  `ToolSearch select:mcp__deepscan__static_scan,mcp__deepscan__scan_family,mcp__deepscan__query_graph,mcp__deepscan__list_graph_questions`
- The helper scripts below ship as `.sh`/`.ps1`/`.py` (same CLI). Run the first
  that works on this OS - **`.sh`** (Linux/macOS) → **`.ps1`** (Windows) →
  **`.py`** fallback (locate Python if it isn't on PATH). See
  [`.claude/scripts/README.md`](../scripts/README.md).

## Scope: `$ARGUMENTS`
- empty / `full` → the whole project (repo root).
- a path (e.g. `src/python`, `infra`) → only that directory.

## Steps (in order)

1. **Zip + upload the project to the MCP.** Over http the project is sent to the
   server, which unzips and scans it. Use the `.sh`/`.ps1`/`.py` form for this OS
   (see Preconditions):
   ```bash
   # Linux/macOS:
   UPLOAD_ID=$(bash .claude/scripts/upload_to_mcp.sh <scope>)      # prints the upload_id
   # Windows:    pwsh -NoProfile -File .claude/scripts/upload_to_mcp.ps1 <scope>
   # Fallback:   "<python>" .claude/scripts/upload_to_mcp.py <scope>
   ```

2. **Scan via the jobs infrastructure.** Call the MCP tool with that id - the
   server enqueues a manual-queue job and the **kruncher fleet** runs it
   (materialize → all scanners → dedupe → report), then returns the consolidated
   report inline:
   - whole project: `static_scan(upload_id=$UPLOAD_ID)`
   - one family: `scan_family(family, upload_id=$UPLOAD_ID)`
   The tool output names the **job number** (`Job #N`) and a summary; the scan
   also appears in the API dashboard.

3. **Return the report to the requester.** Show the summary (counts by severity
   and family, top findings). Persist it under `reports/`:
   ```bash
   mkdir -p reports
   # Linux/macOS (.sh); use .ps1 on Windows or the .py fallback - same args:
   bash .claude/scripts/fetch_report.sh <N> --format json > reports/security-report.json
   bash .claude/scripts/fetch_report.sh <N> --format md   > reports/security-report.md
   ```

4. **Group into a remediation plan** (*local Claude*). Read the report and the
   `analysis` evidence on each finding's `extra` (reachability,
   `reachable_from_entrypoint`, `entry_kind`, `call_path`, `choke_points`). Use
   `query_graph` for precise reachability questions when it helps. Then **group
   the findings by their FIX**, so each group is exactly one reviewable PR:
   - all sinks fixable at one shared helper = one group (e.g. *"parameterize DB
     access in `src/python`"*), not one PR per sink;
   - one group per **direct-dependency CVE** (kind = `dependency`, e.g. *"bump
     `requests` to a fixed version"*);
   - **secrets** get their own group, **report-only** - the fix is removal +
     rotation, never committing the secret;
   - drop findings shown unreachable from any entry point; record them as
     candidate false positives **with the evidence** (do not silently discard).
   For each group capture: a short `title`, a `branch` suggestion
   (`security/<slug>`), `severity` (max of members), `kind`
   (`code` | `dependency` | `secret` | `config`), the affected `files` and
   `findings` ids, the recommended `fix` and the single best `fix_location`, and
   for dependencies the `package` / `current` / `target` versions.

5. **Write the plan.** Save `reports/remediation-plan.json` (machine-readable,
   consumed by `/security-patch`) and `reports/remediation-plan.md` (the human
   review doc), then show the grouped table in chat, ordered by priority
   (risk × ease of fix).

   `remediation-plan.json` shape:
   ```json
   {
     "groups": [
       {
         "id": "g1",
         "title": "Parameterize SQL queries in src/python",
         "branch": "security/sql-injection-src-python",
         "severity": "high",
         "kind": "code",
         "files": ["src/python/sql_injection.py"],
         "findings": ["GP-SAST-001"],
         "fix": "Use parameterized queries via one shared safe query helper.",
         "fix_location": "src/python/sql_injection.py:run_query"
       },
       {
         "id": "g2",
         "title": "Bump requests past its known CVE",
         "branch": "security/bump-requests",
         "severity": "high",
         "kind": "dependency",
         "files": ["deps/requirements.txt"],
         "package": "requests", "current": "2.19.1", "target": "<safe version>",
         "fix": "Bump + migrate API changes + add regression tests."
       }
     ]
   }
   ```

## Output
The grouped, prioritized plan in chat + `reports/remediation-plan.{json,md}` and
the scan report in `reports/security-report.{md,json}`. **No code changes.**
