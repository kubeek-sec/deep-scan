# Development

```bash
uv sync                              # provision the venv (includes the dev group)
uv run pytest                        # the project suite - fast, no external services
```

See [testing.md](testing.md) for the full testing guide, including how to run the
integration, browser e2e and yaml-gated tests that are skipped by default.

## Guinea-pig: triage skill & evaluation command

`guinea-pig/` is a deliberately-vulnerable project (SAST/SCA/secrets/IaC/
pipeline fixtures + a stdlib DAST target) with ground truth in
`expected_findings.json`. Its `.claude/` ships:

- **`security-triage` skill** - scan → normalize/dedupe → **graphoofy** code-graph
  confirmation → risk×ease triage → segmented one-PR-per-finding remediation.
  Improves on naive SAST with evidence-gated verdicts and cross-function
  data-flow analysis.
- **`graphoofy`** (`scripts/codegraph.py`) - a zero-install code-graph analyzer
  that traces untrusted input across function boundaries to confirm a sink is
  reachable, kill false positives, and pick the best fix location. Recognizes
  sanitizers (parameterized queries, `shlex.quote`, `realpath`-and-contain, …)
  so patched code is not re-flagged.
- **`/security-eval` command** - run an evaluation full or per-module, then
  triage and report, cross-checking coverage against the ground truth.

```bash
cd guinea-pig
python3 .claude/skills/security-triage/scripts/codegraph.py paths src/python
python3 dynamic/server.py        # vulnerable DAST target on 127.0.0.1:3000
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the contribution workflow and
coding conventions, and [architecture.md](architecture.md#adding-a-scanner) for
how to add a scanner.
