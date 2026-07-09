"""Integration tests for the shared ad-hoc job path (API/MCP surface).

Run only with a throwaway Postgres in DEEPSCAN_TEST_DB_DSN (see
test_kruncher_store.py for how to start one); otherwise skipped.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

TEST_DSN = os.environ.get("DEEPSCAN_TEST_DB_DSN")
pytestmark = pytest.mark.skipif(not TEST_DSN, reason="DEEPSCAN_TEST_DB_DSN not set")

if TEST_DSN:
    os.environ["DEEPSCAN_DB_DSN"] = TEST_DSN


@pytest.fixture()
def clean_db(tmp_path):
    os.environ["DEEPSCAN_DATA_DIR"] = str(tmp_path / "data")
    from deepscan_jobs import db

    db.init_schema()
    with db.connection() as conn:
        conn.execute(
            "TRUNCATE scan_jobs, job_attempts, scan_results, findings, uploads "
            "RESTART IDENTITY CASCADE"
        )
        conn.commit()
    yield
    db.close_pool()


def _run(coro):
    """Run a coroutine to completion in a worker thread (returning its result or
    re-raising). asyncio.run() then gets a clean loop even if a prior test (e.g.
    Playwright's sync API) left one running on the main thread."""
    import threading

    box: dict = {}

    def _target() -> None:
        try:
            box["result"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller thread
            box["error"] = exc

    thread = threading.Thread(target=_target)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["result"]


def _fixture_project(tmp_path) -> Path:
    # Deliberately-vulnerable snippet written *as a string* into a fixture file so
    # the `analysis` taint scanner has a command-injection sink to detect. It is a
    # scan target only - never executed by the test.
    d = tmp_path / "proj"
    d.mkdir()
    (d / "app.py").write_text(
        "import os\n\ndef handler(value):\n    os.system('echo ' + value)\n",
        encoding="utf-8",
    )
    return d


def test_adhoc_path_scan_runs_and_persists(clean_db, tmp_path):
    from deepscan_jobs import store, worker

    proj = _fixture_project(tmp_path)
    job = store.create_adhoc_job(
        target_type="path",
        target=str(proj),
        scanners=["analysis"],
        surface="test",
        start_running=True,
    )
    assert job["status"] == "running"
    assert job["origin"] == "adhoc"

    report = _run(worker.run_job_inline(job))
    assert report is not None

    done = store.get_job(job["id"])
    assert done["status"] == "done"
    assert done["report_dir"]
    assert (Path(done["report_dir"]) / "report.json").is_file()
    assert (Path(done["report_dir"]) / "report.md").is_file()
    assert done["summary"] is not None
    assert "severity_totals" in done["summary"]

    # The analyzed source is retained and its path recorded on the job. For a
    # local 'path' target the files are referenced in place (never copied/deleted).
    assert done["source_path"]
    assert Path(done["source_path"]).resolve() == proj.resolve()
    assert proj.is_dir() and (proj / "app.py").is_file()

    # Content fingerprint captured (no .git here → git_commit stays null).
    assert done["fingerprint"] and done["fingerprint"].startswith("sha512:")
    assert done["git_commit"] is None

    listed = store.list_jobs(origin="adhoc")
    assert any(j["id"] == job["id"] for j in listed)
    # ad-hoc jobs never write into the discovery results tables.
    assert store.list_jobs(origin="discovery") == []


def test_adhoc_failure_marks_failed(clean_db):
    from deepscan_jobs import store, worker

    job = store.create_adhoc_job(
        target_type="path",
        target="/nonexistent/definitely/not/here",
        scanners=["analysis"],
        surface="test",
        start_running=True,
    )
    with pytest.raises(Exception):
        _run(worker.run_job_inline(job))
    assert store.get_job(job["id"])["status"] == "failed"
