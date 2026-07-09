"""Browser end-to-end tests for the admin UI (Playwright).

Guards the exact display bug that was reported - the right-hand drawer must be
hidden until opened - plus scope create/delete through the real UI.

Requires a throwaway Postgres (DEEPSCAN_TEST_DB_DSN) and the Playwright
chromium browser (`uv run playwright install chromium`). Skipped otherwise.

    DEEPSCAN_TEST_DB_DSN=postgresql://t:t@localhost:55432/deepscan_test \
        uv run pytest tests/test_admin_ui_e2e.py
"""

from __future__ import annotations

import datetime as dt
import os
import socket
import threading
import time
import urllib.request

import pytest

TEST_DSN = os.environ.get("DEEPSCAN_TEST_DB_DSN")
pytestmark = pytest.mark.skipif(not TEST_DSN, reason="DEEPSCAN_TEST_DB_DSN not set")

if TEST_DSN:
    os.environ["DEEPSCAN_DB_DSN"] = TEST_DSN

playwright = pytest.importorskip("playwright.sync_api")
expect = playwright.expect


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _seed_scanned_source() -> None:
    """Insert one scope + source + a scan result so the dashboard has data."""
    from deepscan_core import Mode, Report, Severity
    from deepscan_core.models import DedupedFinding
    from deepscan_input_connector_base import KIND_DIRECTORY, DiscoveredSource
    from deepscan_kruncher import store

    scope = store.upsert_scope(
        name="seed", connector="directory", scope_config={"base_path": "/tmp"}
    )
    src = store.upsert_source(
        scope["id"],
        DiscoveredSource(
            external_id="/tmp/seed", kind=KIND_DIRECTORY, name="seed-src", location="/tmp/seed"
        ),
    )
    job = store.enqueue_scan(src["id"], target_revision="rev")
    claimed = store.claim_job("seed-worker")
    report = Report(
        mode=Mode.STATIC,
        target="/tmp/seed",
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        duration=1.0,
        tools=[],
        findings=[
            DedupedFinding(
                severity=Severity.HIGH, location="a.py:1", message="issue",
                tools=["opengrep"], rules=["r"], families=["sast"], cwes=["CWE-1"],
                occurrences=1, fingerprints=["fp"],
            )
        ],
    )
    store.persist_success(claimed, report, duration=1.0)
    _ = job


@pytest.fixture(scope="module")
def live_server():
    import uvicorn

    from deepscan_kruncher import db
    from deepscan_kruncher_admin.main import create_app

    db.init_schema()
    with db.connection() as conn:
        conn.execute(
            "TRUNCATE scopes, sources, scan_jobs, job_attempts, scan_results, findings "
            "RESTART IDENTITY CASCADE"
        )
        conn.commit()
    _seed_scanned_source()

    port = _free_port()
    config = uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/api/overview", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    yield base
    server.should_exit = True
    thread.join(timeout=5)
    db.close_pool()


def test_drawer_is_hidden_until_opened(page, live_server):
    page.goto(live_server)
    drawer = page.locator("#drawer")
    # The reported bug: an empty panel on the right covering the screen.
    expect(drawer).to_be_hidden()

    # Open it from the dashboard's "Top exposed sources" table.
    page.get_by_role("button", name="view").first.click()
    expect(drawer).to_be_visible()
    expect(drawer).to_contain_text("seed-src")

    # And it must close again.
    page.locator("#drawer-close").click()
    expect(drawer).to_be_hidden()


def test_create_and_delete_scope_through_ui(page, live_server):
    page.goto(live_server)
    page.get_by_role("button", name="Scopes").click()
    page.get_by_role("button", name="+ Add scope").click()

    modal = page.locator(".modal")
    expect(modal).to_be_visible()
    page.locator("#f-name").fill("ui-made")
    page.locator("#f-connector").select_option("directory")
    page.locator("#f-config").fill('{"base_path": "/tmp"}')
    modal.get_by_role("button", name="Create", exact=True).click()

    # The new scope appears in the table.
    expect(page.locator("#scopes-table")).to_contain_text("ui-made")

    # Delete it (confirm in the modal). Scope the modal button so it doesn't
    # collide with the row's lowercase "delete" links.
    page.locator("tr", has_text="ui-made").get_by_role(
        "button", name="delete", exact=True
    ).click()
    page.locator(".modal").get_by_role("button", name="Delete", exact=True).click()
    expect(page.locator("#scopes-table")).not_to_contain_text("ui-made")
