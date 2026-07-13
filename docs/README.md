# Deep Scan documentation

Start with the [project README](../README.md) for the highlights and quick
start. The detailed reference lives here:

| Doc | What's inside |
|---|---|
| [overview.md](overview.md) | Screenshot tour of the main functions: the agent/IDE MCP server, the kruncher/ASPM dashboard, the self-serve web app |
| [architecture.md](architecture.md) | Monorepo layout, the uv workspace, the two-phase analysis model, how to add a scanner, the security model, telemetry |
| [scanners.md](scanners.md) | Full scanner catalog + deep dives: `analysis` code-graph, `codeql`, secret engines, `plumber`, `reachable-deps`, `ai-analysis` |
| [severity-mapping.md](severity-mapping.md) | How each scanner's native severity is normalized to Deep Scan's critical/high/medium/low/info scale, and what each level means concretely |
| [interfaces.md](interfaces.md) | CLI, MCP server, REST API + web app, CI-template generator, logging |
| [mcp-setup.md](mcp-setup.md) | Drop `.claude/` + `.mcp.json` into your own project to drive the MCP server — including pointing `.mcp.json` at a remote server's IP |
| [deployment.md](deployment.md) | Continuous scanning (connectors, kruncher, ASPM), Docker Compose scaling, Kubernetes/Kustomize, scan isolation, shared Trivy server |
| [development.md](development.md) | Dev setup, the guinea-pig fixtures and skills |
| [testing.md](testing.md) | Running the test suite, and how to run everything including the DB/browser/yaml-gated tests |
| [graph/](graph) | The code-graph schema and terminology backing the `analysis` engine |

See also [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md).
