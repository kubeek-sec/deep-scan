# Testing

The suite lives in [`tests/`](../tests) and is driven by `pytest` (configured in
[`pyproject.toml`](../pyproject.toml), `[tool.pytest.ini_options]`).

## Quick run

```bash
uv sync                 # once, to provision the venv (installs the dev group: pytest, …)
uv run pytest           # the full project suite - fast, no external services
```

This runs everything that does not need an external service (~186 tests in a few
seconds). Tests that require a database, extra browsers, or optional packages are
**skipped** rather than failed, so a clean checkout stays green out of the box.

Useful variants:

```bash
uv run pytest -rs                       # also print why each test was skipped
uv run pytest tests/test_codeql.py      # a single file
uv run pytest -k connector              # tests whose name matches a pattern
uv run pytest -q                        # quiet (one char per test)
```

## Running *all* tests, including the skipped ones

A default `uv run pytest` reports ~30 skips. They fall into three groups; satisfy
all of them and nothing is skipped. Use `uv run pytest -rs` to see the live list.

| Skipped | Count | What it needs |
|---|---|---|
| `DEEPSCAN_TEST_DB_DSN not set` | 20 | A throwaway Postgres (queue/result store, admin & REST API, ad-hoc jobs, admin UI e2e, one MCP upload test) |
| `could not import 'yaml'` | 10 | The optional `pyyaml` package (CI pipeline-template generator tests) |
| Playwright browser | - | The Chromium browser, for the admin UI e2e suite (these are also gated on the DB DSN above) |

Putting it together - spin up the Postgres, install the browser once, and pass
`pyyaml` for the run:

```bash
# 1. Throwaway Postgres for the integration + e2e tests
docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=t -e POSTGRES_USER=t \
    -e POSTGRES_DB=deepscan_test --name dstest postgres:16-alpine

# 2. Chromium for the Playwright admin-UI tests (once)
uv run playwright install chromium

# 3. Run the whole suite with nothing skipped
DEEPSCAN_TEST_DB_DSN=postgresql://t:t@localhost:55432/deepscan_test \
    uv run --with pyyaml pytest -rs

# Tear down the database when done
docker rm -f dstest
```

`uv run --with pyyaml` pulls `pyyaml` in just for that invocation, without
touching the project's dependencies. Alternatively, install it into the venv
(`uv pip install pyyaml`) if you run these often.

The Playwright suite (`tests/test_admin_ui_e2e.py`) drives the real admin UI in a
browser - it guards, among other things, that the right-hand detail drawer stays
hidden until a row is opened.

> Note: the `pytest`-reported *skips* above are environment-gated whole tests.
> Many scanner tests also assert a clean **`skipped` scanner status** when a tool
> binary (Cisco, ClamAV, Checkov, CodeQL, trivy, …) is absent - that is the
> behaviour under test and needs no setup.

See [development.md](development.md) for the broader dev setup and the guinea-pig
fixtures, and [CONTRIBUTING.md](../CONTRIBUTING.md) for the contribution workflow.
