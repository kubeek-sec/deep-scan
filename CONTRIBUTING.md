# Contributing to Deep Scan

Thanks for helping improve Deep Scan. This guide keeps contributions simple and
consistent. For the bigger picture, read the
[architecture overview](docs/architecture.md) first.

## Ground rules

- **No malicious or destructive code - ever.** This is a security project with a
  deliberately-vulnerable test target (`guinea-pig/`). Proof-of-concept and
  remediation examples must be **harmless**: the only side effects allowed are
  creating a marker file (e.g. `touch pwned-<branch>.txt`) or a request to a
  fictitious `*.kubeek.com` address. Never add anything that changes machine
  state - no `rm`/`rm -rf`, no real exfiltration, no real exploit payloads.
- **A scanner never crashes the run.** It must report `ok`, `skipped`, or
  `error` - never raise. Subprocesses run with `shell=False` and a hard timeout.
- **Don't commit secrets or scan artifacts.** Reports, clones and downloaded
  tools are git-ignored; keep it that way.

## Setup

It is a [uv](https://docs.astral.sh/uv/) workspace (Python 3.13).

```bash
uv sync
uv run deepscan tools install all   # optional: pinned, checksum-verified tools
```

## Develop

- **Code style:** format and lint with [ruff](https://docs.astral.sh/ruff/)
  before pushing:

  ```bash
  uv run ruff format .
  uv run ruff check .
  ```

- **Match the surrounding code.** New code should read like the file it lives in
  - same naming, idioms and comment density. Keep the small, auditable knowledge
  bases (e.g. `analysis/sinks.py`) easy to review.

- **Adding a scanner** is mechanical - pin the tool, subclass `Scanner`,
  register it. Every front-end (CLI, MCP, API) then picks it up automatically.
  Full steps: [docs/architecture.md](docs/architecture.md#adding-a-scanner).

## Test

```bash
uv run pytest                        # fast: connectors, schema parity (no DB)
```

Integration and browser e2e tests need a throwaway Postgres (and Playwright's
chromium for the admin UI) - see
[docs/development.md](docs/development.md) for the full command. Run the relevant
suite for anything touching the job queue, the API, or the admin dashboard.

If you change scanner behavior, validate against the bundled fixtures:

```bash
uv run deepscan scan ./guinea-pig
```

and update `guinea-pig/expected_findings.json` when the ground truth genuinely
changes (explain why in the PR).

## Commits & pull requests

- Write focused commits with clear messages (imperative mood, e.g. "add checkov
  scanner"). Keep unrelated changes in separate PRs.
- Before opening a PR, make sure:
  - [ ] `uv run ruff check .` and `uv run ruff format .` are clean
  - [ ] `uv run pytest` passes (plus the integration suite if you touched the
        DB/API/admin)
  - [ ] docs are updated when behavior, flags or env vars change
        (README highlights stay short - details go under `docs/`)
  - [ ] no secrets, scan reports, or destructive code are included
- Describe **what** changed and **why**, and how you verified it (commands +
  output). Link any related TODO item.

## Reporting bugs & ideas

Open an issue with steps to reproduce (a minimal target helps) and the relevant
`deepscan` output. For **security vulnerabilities**, do **not** open a public
issue - follow [SECURITY.md](SECURITY.md).
