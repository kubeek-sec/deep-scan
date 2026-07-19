---
description: Security evaluation - zip the project, scan it through the Deep Scan MCP (jobs infrastructure), return the report, and group the findings into a prioritized, PR-ready remediation plan.
argument-hint: "[path to scan | 'full'] (default: whole project)"
---

# /security-eval

Evaluate the security of this project and produce a **prioritized remediation
plan, grouped so each group becomes one easy-to-review PR**. The scan runs
server-side on the Deep Scan **jobs infrastructure** (the kruncher fleet); this
session - *local Claude* - does the **reachability verification**, prioritization
and grouping (scanners detect patterns; local Claude confirms them in source).
This command only evaluates and plans; it changes no code. Run `/security-patch`
to implement.

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

   > **Timeout resilience - do NOT re-scan.** A long scan can outlast the MCP
   > client session (`MCP server "deepscan" session expired`). The scan is a
   > server-side **job** that keeps running and finishes anyway - treat that error
   > as EXPECTED, not a failure: **recover the existing job, never re-upload.** One
   > command resolves the upload, waits for it, and pulls the report:
   > ```bash
   > bash .claude/scripts/fetch_report.sh "$UPLOAD_ID" --wait --format json > reports/security-report.json
   > bash .claude/scripts/fetch_report.sh "$UPLOAD_ID" --wait --format md   > reports/security-report.md
   > ```
   > (`fetch_report` takes a `Job #N` *or* an `upload_id`; `--wait` polls until the
   > job is `done`.) That already satisfies step 3 - continue at step 4. Raising
   > `MCP_TOOL_TIMEOUT` (`.claude/settings.json`, needs a `claude` restart) widens
   > the window, but recovery-by-job is the durable fix: a dropped session must
   > never trigger a fresh scan of the same upload.

3. **Return the report to the requester.** Show the summary (counts by severity
   and family, top findings). Persist it under `reports/`:
   ```bash
   mkdir -p reports
   # Linux/macOS (.sh); use .ps1 on Windows or the .py fallback - same args:
   bash .claude/scripts/fetch_report.sh <N> --format json > reports/security-report.json
   bash .claude/scripts/fetch_report.sh <N> --format md   > reports/security-report.md
   ```

4. **Verify reachability before grouping - step back from the pattern**
   (*local Claude*). A scanner reports a *pattern match* plus a *heuristic* guess
   at the entry point/taint; it does not know this codebase. Scanners **detect**;
   this step **confirms**. Before any finding can become a group, confirm or
   refute it by **reading the code at the scanned commit** (grep the callers, open
   the sink, trace the source). Do this for every `critical`/`high` and a sample
   of `medium`; skip only obvious noise families unless they cluster. For each
   finding answer:

   1. **Exists?** Is the flagged version/line/secret actually present in the
      *current tree*, or is it stale, mis-resolved, or only in git history?
   2. **Shipped code?** Is the sink in runtime/library code, or in
      test / benchmark / example / docs / build-or-maintenance tooling / vendored
      `externals`? Record which.
   3. **Really tainted?** Trace the "untrusted input" to its origin. An internal
      constant, a trusted API response, or a maintainer prompt is **not** attacker
      input. Note constraints that neuter the pattern (charset, type, length).
   4. **Reachable trigger?** Is the path driven by an automated / remote /
      attacker-reachable entry point (server route, CI job, packaging/build hook,
      import side-effect) - or only by a manual, interactive, privileged operator?
      Grep the invocation sites; check CI/build wiring. Use `query_graph`
      (`attack_paths`, `endpoints_reach_sink`, `blast_radius`) to confirm/refute
      the call path when a manual read is ambiguous, and read the `analysis`
      evidence on each finding (reachability, `reachable_from_entrypoint`,
      `entry_kind`, `call_path`, `choke_points`).
   5. **Already mitigated?** Existing sanitizer / allowlist / checksum / safe API
      (`tarfile filter="data"`, list-form `subprocess`, parameterized query,
      cross-host auth stripping, …)?

   Assign each finding a **verdict + one-line evidence (`file:line` + why)**:
   - `exploitable` - real, reachable, unmitigated → becomes a fix group.
   - `latent` - real weakness but no current reachable trigger → optional
     **defense-in-depth** group, labelled as such; do **not** inflate its severity.
   - `false_positive` - the pattern doesn't hold (source not tainted / already
     mitigated / artifact absent) → dropped **with evidence**.
   - `by_design` - documented intended behaviour (e.g. `pickle` model load) →
     dropped **with evidence**.

   Set an `effective_severity` (may differ from the scanner's) and **prioritise
   and group on that, not the raw label.** Only `exploitable`/`latent` findings
   become groups; `false_positive`/`by_design` go to the plan's `dismissed` list -
   **never silently discarded.**

   For each `exploitable`/`latent` finding also capture a short **impact
   assessment** that justifies `effective_severity` and tells `/security-patch`
   what to reproduce at the product level: `exploit_difficulty`
   (*trivial | moderate | hard* - preconditions, privileges, whether the attacker
   supplies the input, network position), `affected_parties` (**who supplies the
   malicious artifact vs. who is harmed** - a library *user* loading an untrusted
   dataset/model, a *maintainer*/build script, a *CI job*, a *downstream service*),
   `attack_vector` (how the artifact reaches the sink), and `impact` (CIA + class:
   RCE / arbitrary write / path traversal / SSRF / info-leak / DoS + blast radius
   in this product's context).

5. **Group into a remediation plan** (*local Claude*). Taking only the verified
   `exploitable`/`latent` findings from step 4, **group them by their FIX**, so
   each group is exactly one reviewable PR:
   - all sinks fixable at one shared helper = one group (e.g. *"parameterize DB
     access in `src/python`"*), not one PR per sink;
   - one group per **direct-dependency CVE** (kind = `dependency`, e.g. *"bump
     `requests` to a fixed version"*). Set `target` to a **real, published**
     release of the same package that clears the CVE and is not itself vulnerable
     or yanked - prefer the **lowest** such version, never a guessed or
     typosquatted name (`/security-patch` re-verifies this before bumping);
   - **secrets** get their own group, **report-only** - the fix is removal +
     rotation, never committing the secret.
   Capture each group with the fields in the schema below: `title`, `branch`
   (`security/<slug>`), `kind` (`code`|`dependency`|`secret`|`config`), the step-4
   `verdict` / `effective_severity` (max of members) / `reachability` / `evidence` /
   `impact`, the affected `files` and `findings`, the `fix` and single best
   `fix_location`, and for dependencies `package`/`current`/`target`.

6. **Write the plan.** Save `reports/remediation-plan.json` (machine-readable,
   consumed by `/security-patch`) and `reports/remediation-plan.md` (the human
   review doc), then show the grouped table in chat, ordered by priority
   (risk × ease of fix).

   `remediation-plan.json` shape (every group carries its step-4 `verdict`,
   `effective_severity`, `reachability` and `evidence`; dismissed findings are
   recorded, never dropped):
   ```json
   {
     "groups": [
       {
         "id": "g1",
         "title": "Parameterize SQL queries in src/python",
         "branch": "security/sql-injection-src-python",
         "verdict": "exploitable",
         "effective_severity": "high",
         "kind": "code",
         "reachability": "reachable from POST /search handler (run_query)",
         "evidence": "src/python/sql_injection.py:41 - request `q` reaches cursor.execute() unsanitized",
         "impact": {
           "exploit_difficulty": "trivial",
           "affected_parties": "victim: anyone whose data is in the DB; attacker: any unauthenticated web client",
           "attack_vector": "crafted `q` query parameter in an HTTP request to /search",
           "impact": "SQL injection - read/modify arbitrary rows (confidentiality + integrity); high blast radius"
         },
         "files": ["src/python/sql_injection.py"],
         "findings": ["GP-SAST-001"],
         "fix": "Use parameterized queries via one shared safe query helper.",
         "fix_location": "src/python/sql_injection.py:run_query"
       },
       {
         "id": "g2",
         "title": "Bump requests past its known CVE",
         "branch": "security/bump-requests",
         "verdict": "exploitable",
         "effective_severity": "high",
         "kind": "dependency",
         "reachability": "imported by the request-handling path; version present in deps/requirements.txt",
         "evidence": "deps/requirements.txt:12 - requests==2.19.1 (CVE-XXXX-YYYY, fixed in 2.32.4)",
         "files": ["deps/requirements.txt"],
         "package": "requests", "current": "2.19.1", "target": "<safe version>",
         "fix": "Bump + migrate API changes + add regression tests."
       }
     ],
     "dismissed": [
       {
         "finding": "CWE-502 pickle.loads @ src/ml/estimator_checks.py:2806",
         "verdict": "by_design",
         "evidence": "documented model-persistence API; input is a trusted fixture, not remote"
       },
       {
         "finding": "CWE-918 requests.get @ tools/fetch_authors.py:29",
         "verdict": "latent",
         "evidence": "URL base hardcoded, source charset-constrained, script is manual/admin-only - no build/CI trigger"
       }
     ]
   }
   ```

## Output
The **verified**, grouped, prioritized plan in chat + `reports/remediation-plan.{json,md}`
(each group with its `verdict`/`effective_severity`/`reachability`/`evidence`, plus
the `dismissed` findings and why) and the scan report in
`reports/security-report.{md,json}`. **No code changes.**
