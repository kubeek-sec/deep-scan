# Scanners

Every scanner emits the same normalized `Finding`s, so they all flow through
dedup, the four report formats (JSON/Markdown/HTML/SARIF), the API/kruncher and
the ASPM dashboard. Adding one is mechanical - see
[architecture.md](architecture.md#adding-a-scanner).

## Catalog

| Family | Scanner(s) | Tool |
|---|---|---|
| SAST | `opengrep` | pattern-based code analysis (semgrep-compatible) |
| SAST | `codeql` | CodeQL interprocedural taint/dataflow (needs the CodeQL CLI bundle; skips until installed) |
| SAST | `cisco-ai-skill-scanner` | AI agent skill security: prompt injection, data exfiltration, malicious code (Cisco AI Defense; installed via `uv`, skips until installed) |
| SCA | `trivy`, `osv-scanner` | dependency vulnerabilities |
| Secret | `gitleaks`, `trufflehog`, `nosey_parker`, `titus`, `betterleaks`, `kingfisher` | hardcoded secrets (multiple engines, deduplicated) |
| IaC | `trivy-misconfig` | Terraform/K8s/Dockerfile/Helm misconfig |
| IaC | `checkov` | Terraform/CloudFormation/K8s/Helm/Dockerfile/ARM/Actions misconfig (Bridgecrew Checkov; installed via `uv`, skips until installed) |
| License | `trivy-license` | dependency license compliance |
| Malware | `clamav` | virus/malware signatures (system `clamscan`; skips until installed) |
| Malware | `yara` | malicious-intent YARA signatures: prompt injection, tool poisoning, command/SQL/script/code injection, credential harvesting, data exfiltration, system manipulation (rules from Cisco's Apache-2.0 [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)) |
| Malware | `mcp-threats` | malicious-intent **text** patterns in docstrings/descriptions/markdown: instruction override, hidden behavior, tool poisoning, exfiltration + invisible/bidi Unicode |
| DAST | `nuclei`, `zaproxy` | dynamic scanning of a running URL (ZAP via Docker) |
| Pipeline | `plumber` | CI/CD compliance: action/image pinning, branch protection, pipeline secrets |
| Analysis | `analysis` | graphoofy code-graph + taint/missing-sanitization analysis (no AI) |
| Analysis | `reachable-deps` | correlates SCA dependency CVEs with actual imports/usage + reachability (no AI) |
| AI | `ai-analysis` | LLM triage/prioritization over all scanners' findings, **off by default** |

## `analysis` - code-graph security analysis (no AI)

`analysis` builds a **code graph** of the target with the vendored
[graphoofy](../packages/graphoofy) engine (tree-sitter, multi-language) - a knowledge
base of files, functions, imports and calls written out as `graph.json` and an
interactive `graph.html` - and layers a deterministic security analysis over it.

The `graph.html` (vis-network, in the report's `raw/` dir) is an **interactive
security graph** built from a precomputed, security-annotated payload
([`analysis/graph_view.py`](../packages/core/src/deepscan_core/analysis/graph_view.py)),
following the model in [`docs/graph`](graph). Nodes carry a **type** (file/
class/function/library/symbol - color) and security **tags** (SINK/CRITICAL/
ENTRY/SANITIZER - border) and **metrics** (degree, fan-in/out, pagerank,
reachable_sinks, hotness); **size ∝ degree**. Node **positions are precomputed**
so it loads instantly (physics off) and stays stable across interactions.

- **General view**: pan/zoom, filter by node type / edge relation / minimum
  degree, free-text search; double-click a node to **cascade** (keep only what
  it reaches), double-click again to restore.
- **Ctrl+drag** a node moves its whole connected component rigidly; **box/shift-
  select + right-click** opens a menu to re-lay-out just the selection (force or
  circle), isolate it, or select all visible.
- A **Layer** dropdown answers the AppSec questions over the same view:
  *Unsanitized sources*, *Critical functions*, *Endpoints → sink*, *Endpoints →
  taint*, *Shortest/All paths → critical*, *External dependencies*, *Vuln deps →
  critical*, *Attack paths (by impact)*, *Blast radius* (click a node → its
  callers + everything it reaches light up).

Depth is bounded by the extraction: precise taint/sinks are Python-only (other
languages are structural), and external-dependency/CVE layers are best-effort
here - the `reachable-deps` scanner + `ai-analysis` triage do the real
SCA correlation. There is no CFG/DFG/trust-boundary modelling yet.

The security analysis over the graph:

- **One taint engine, every language** - a single source→sink propagation core
  (`analysis/taint_core.py`) proves untrusted input reaching a dangerous sink
  *across function boundaries*, sanitizer-aware, so patched code is not
  re-flagged. **Python** feeds it from a precise `ast` collector - with
  **import-alias resolution**, so `from os import system as run; run(x)` is
  still matched to `os.system`; **every other language** (JS/TS, Java, Go, Ruby,
  PHP, C/C++, C#, Rust) feeds it from a tree-sitter collector. All produce
  identical, proven taint paths with a per-family `engine` label and a chain.
- **Per-finding confidence** - `high` when the sink-bearing function itself
  reads an explicit untrusted source, otherwise `medium` (the untrustedness is a
  parameter assumption) until reachability confirms exposure (below). The basis
  is in `extra.features.source_evidence`.

The knowledge base (`analysis/sinks.py`, small and auditable) is more than a flat
sink list:

- **Kind-specific sanitizers** - a sanitizer clears only the vuln *classes* it
  neutralises, so an `html.escape`-d value still trips a SQL sink while an XSS
  sink is cleared (`SANITIZERS` maps each name to its kinds).
- **Parameter-level sinks** - only the *dangerous argument* counts, so
  `requests.get(SAFE_URL, params=tainted)` is not SSRF and
  `cursor.execute(sql, tainted_params)` is not SQL-injection (`SINK_ARGS`).
- **Safe-form recognition** - structurally-safe shapes are not flagged:
  parameterized queries, `subprocess` with an argument list, `yaml.load` with a
  `SafeLoader` (keyword or positional), `torch.load(weights_only=True)`.
- **Triage breadcrumbs** - each finding's `extra.features` carries
  `source_evidence`, `cross_function`/`hops` and `sanitized_other_kind`.

Every finding is then enriched with **call-graph reachability** computed over
the graphoofy graph: is the enclosing function reachable from an **entry point**
(an HTTP handler, a CLI `main`, an exported/uncalled function), by what **call
path**, and at what **distance**? Each finding's `extra` carries
`reachable_from_entrypoint`, `entry_point`, `entry_kind` (web/cli/exported/
internal) and `call_path`. A confirmed path from a web/CLI entry point is
evidence of real exposure, so it raises a `medium` finding to `high` (and is fed
to `ai-analysis`); a sink only reachable from internal code is left
conservative.

It also computes **choke points** - using the call-graph **dominator tree**
(from a virtual super-source over all entry points) plus **betweenness
centrality**. A choke point is a function that *every* path to a finding's sink
must pass through, so a single validation placed there neutralises the issue on
all paths; ranking by how many distinct findings each one covers answers "fix
here to mitigate N issues at once". Findings carry `extra.choke_points` (the
best fix locations) and the run summary lists the top choke points - both fed to
`ai-analysis` so its recommendations point at shared fixes.

It needs no external binary - it is **on by default**. The sink/source/
sanitizer knowledge base lives in `packages/core/.../analysis/sinks.py` (small
and auditable). A reviewer can accept a specific sink with an inline `# nosec`
comment on the sink line - blanket, or scoped by kind/CWE (`# nosec
sql-injection`, `# nosec CWE-89`); suppressions are counted in the run summary
(`suppressed_by_nosec`), never silently dropped.

```bash
uv run deepscan scan ./my-project --scanner analysis
```

## `codeql` - deep interprocedural SAST (off by default)

For type-aware, interprocedural taint/dataflow well beyond the built-in
`analysis` engine, the `codeql` scanner wraps the **CodeQL CLI**. We don't build
CodeQL or touch its database format - we run `codeql database create` then
`codeql database analyze … --format=sarif-latest` and parse the SARIF into normal
`Finding`s. Install the pinned, checksum-verified **CodeQL CLI bundle** the same
way as every other tool - `deepscan tools install codeql` (a ~0.5–1.1 GB
directory tree extracted under the tools dir; the install also pre-fetches the
standard CodeQL **query packs** so analysis works out of the box) - or point at
your own with `DEEPSCAN_CODEQL_BIN` / a `codeql` on PATH. The CLI bundle ships no
query packs, so analysis runs with `--download` to fetch any missing pack on
first use (cached under `~/.codeql/packages`). It is **off by default** (slow and
RAM-heavy) - opt in with `CODEQL=true`; once enabled it still shows up as skipped
with an install hint until the CLI bundle is installed, so it never silently
disappears.
Buildless for Python/JS/TS/Ruby; Java/C# use `--build-mode=none`; Go/C++/Swift
need a build command via `DEEPSCAN_CODEQL_BUILD_<LANG>` (else that language is
skipped). Knobs: `DEEPSCAN_CODEQL_SUITE[_<LANG>]`, `DEEPSCAN_CODEQL_THREADS`,
`DEEPSCAN_CODEQL_EXTRA_ARGS`, `DEEPSCAN_TIMEOUT_CODEQL`. Note: CodeQL on private
code requires a GitHub licence; it is slow and RAM-heavy.

## Secret scanners

Six secret engines run in the `secret` family and are deduplicated together:
`gitleaks` and `trufflehog` (managed tools), plus four from Praetorian/MongoDB -
**`nosey_parker`** (regex + entropy), **`titus`**, **`betterleaks`** (the
Gitleaks successor) and **`kingfisher`** (MongoDB). All four install like any
tool (`deepscan tools install nosey_parker titus betterleaks kingfisher`), run
**fully local** (no credential validation / no outbound calls), emit SARIF, and
are on by default - disable any with its env toggle (e.g. `KINGFISHER=false`).

**Git-history aware.** All six scan the **full commit history** when the target
is a git checkout (a `.git` dir or file) - a secret that was committed and later
removed is still in the history and still a leak - and fall back to a plain
working-tree scan when there is no `.git`. The switch is automatic per target
(`scanners/base.py:is_git_repo`): `gitleaks`/`betterleaks` use their `git`
subcommand (else `dir`), `trufflehog` uses its `git file://<repo>` source (else
`filesystem`), and `titus` passes `--git`; `nosey_parker` and `kingfisher` walk
history by default (`--git-history=full`) so they need no switch. History hits
carry the introducing commit (in the finding message / location) for triage.

## `plumber` - CI/CD pipeline compliance

`plumber` audits pipeline/CI configuration (GitHub Actions / GitLab CI) for
risky patterns - unpinned images and actions, action CVEs, branch-protection
gaps, unsafe scripts, secrets in pipeline YAML. Install it like any tool
(`deepscan tools install plumber`), then it runs by default in static scans
(`plumber analyze --sarif …`, parsed into normal `Finding`s, family `pipeline`).

**Provider detection.** Plumber natively picks GitHub vs GitLab from the git
remote, which fails when the target has no `.git` (a copy-pasted repo) or no
configured remote. We instead detect it from on-disk markers - a
`.github/workflows/` dir with a workflow YAML → GitHub, a root `.gitlab-ci.yml`
→ GitLab - and force it with `--provider`, so a scan runs whenever there is CI
config to audit (and skips cleanly when there is none). The **GitHub** path is a
local scan of `.github/workflows` (no token); when the target has no git remote
we hand plumber a throwaway git dir in the scratch area (a placeholder remote, no
commit) so it can still derive an owner/repo - the scanned repo is never written
to. The **GitLab** path is API-only (it fetches CI config + project settings), so
it needs a real remote plus `GITLAB_TOKEN`; with no remote there is nothing to do
locally and it skips.

Provider-specific checks (action CVEs, branch protection) use `GH_TOKEN` /
`GITHUB_TOKEN` / `GITLAB_TOKEN` from the environment when present and are skipped
otherwise. Plumber needs a `.plumber.yaml` policy - we use the repo's own if
present, else generate the default into the scratch dir (the scanned repo is
never modified). Disable with `PLUMBER=false`.

## `reachable-deps` - are the vulnerable dependencies actually used?

A deterministic **consumer** scanner (runs in phase 2): it reads the SCA
findings (`trivy` / `osv-scanner`) and crosses each against the code graph's
`imports` edges. For every dependency CVE it reports a verdict - **used**
(imported by N files; and whether any is reachable from an entry point) or
**not-found** (no matching import in the scanned source → likely unused,
transitive or dynamically loaded). A used-and-reachable CVE keeps its severity;
an unimported one is downgraded. This cuts the CVE noise to what is actually
exercised. The import-name ↔ package-name match is a heuristic (with a small
alias table), so verdicts carry a confidence and a CVE is never silently hidden.
On by default; skips when there are no SCA findings.

## `ai-analysis` - LLM triage over every finding (off by default)

`ai-analysis` is a **consumer** scanner: it reads the findings produced by all
the other scanners (via `ScanContext.prior_findings`) and drives the headless
Claude CLI to (1) assess the **real risk** each finding carries - what an
attacker can actually achieve - (2) **deduplicate and prioritize** them
(P0–P3), flagging likely false positives, and (3) recommend remediation. It
inspects the code **read-only** (Read/Grep/Glob, `--permission-mode dontAsk`,
`--setting-sources user` so the untrusted repo's `.claude/` is never loaded) and
**never edits files or opens PRs**.

Its output is a structured **triage** surfaced three ways: a **console summary**,
a **dedicated report** (`triage.json` / `triage.md` / `triage.html` next to the
normal report - the human-facing real-risk/remediation document), and the
`triage` field of the JSON report (and the API `GET /scans/{id}/triage`).

It is **off by default** (needs the `claude` CLI and a model). Naming it (or its
env toggle) auto-runs the default producer scanners first so it always has
something to triage:

```bash
# CLI - runs the producers, then triages:
uv run deepscan scan ./my-project --scanner ai-analysis
# as part of a full scan, opt in with the env toggle:
AI_ANALYSIS=true uv run deepscan scan ./my-project
# MCP - scan_with(scanner="ai-analysis", ...) ; Kruncher - set AI_ANALYSIS=true on the worker.
```

**Pointing it at a local model (save tokens).** The scanner shells out to
`claude` inheriting the environment, configurable three ways (highest precedence
first): real env vars → a settings file you pass → your user
`~/.claude/settings.json`.

```bash
# (a) env vars - e.g. LM Studio:
export ANTHROPIC_BASE_URL=http://192.168.1.43:1234
export ANTHROPIC_AUTH_TOKEN=lmstudio
export ANTHROPIC_MODEL=foundation-sec-1.1-8b-instruct@q8_0
# (b) a settings.json with an `env` block (see deploy/docker/claude-settings.example.json):
export DEEPSCAN_CLAUDE_SETTINGS=/path/to/claude-settings.json   # -> claude --settings
```

Knobs (env): `DEEPSCAN_CLAUDE_BIN`, `DEEPSCAN_CLAUDE_MODEL` (→`--model`),
`DEEPSCAN_CLAUDE_SETTINGS` (→`--settings`), `DEEPSCAN_CLAUDE_SETTING_SOURCES`,
`DEEPSCAN_CLAUDE_PERMISSION_MODE`, `DEEPSCAN_CLAUDE_ALLOWED_TOOLS`,
`DEEPSCAN_CLAUDE_EXTRA_ARGS`, `DEEPSCAN_TIMEOUT_AI_ANALYSIS`. In Docker, build
with `--build-arg INSTALL_CLAUDE=true` and put the model env/`AI_ANALYSIS=true`
in `deploy/docker/.env`; in Kubernetes, add them to the `deepscan-secrets`/config.

**Full conversation logging.** ai-analysis drives Claude with
`--output-format stream-json`, so the **entire conversation** - every assistant
turn and every tool call the model makes to read the code, plus the final answer
- is logged (the `deepscan.ai-analysis` logger, at INFO by default; set
`DEEPSCAN_AI_LOG_CONVERSATION=false` to drop it to DEBUG) and persisted under the
report's `raw/`: `ai-analysis.prompt.md`, `ai-analysis.transcript.jsonl` (the raw
stream), `ai-analysis.transcript.txt` (readable) and `ai-analysis.result.txt`.

If the model output can't be parsed, `ai-analysis` falls back to a deterministic
severity-ordered triage so the report is never empty (clearly labeled).
