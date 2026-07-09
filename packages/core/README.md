# deepscan-core

Core library shared by the Deep Scan MCP server, CLI and REST API.

- `models` - normalized `Finding` / `ToolResult` / `Report` schema (severity, family, fingerprints)
- `scanners` - one module per tool; every scanner implements the same small contract (producers, plus *consumer* scanners like `ai-analysis` / `reachable-deps`)
- `analysis` - code-graph security engine: taint, tree-sitter sinks, reachability, choke points, the security graph payload (`graph_view`) + interactive `graph.html`, and the `query` layer
- `ai` - headless Claude CLI helper + triage prompt for `ai-analysis`
- `install` - secure tool installation: pinned versions, SHA-256 verification, safe extraction (incl. directory-tree tools like CodeQL)
- `runner` - two-phase orchestration: producers run first, then consumers read their findings; dedupe; build a `Report`
- `reporting` - render a `Report` to Markdown, JSON, HTML, SARIF (+ the triage report), with a shared dark/branded theme matching the web app
- `metrics` - anonymous, opt-in Sentry telemetry (no-op without `SENTRY_DSN`)
- `log` - centralized `deepscan.*` logging (INFO default, DEBUG via env)

See the repository root README for the scanner-implementation contract.
