"""Integration tests for the Postgres-backed queue and result store.

These run only when a throwaway Postgres is provided via DEEPSCAN_TEST_DB_DSN,
e.g.:

    docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=t -e POSTGRES_DB=deepscan_test \
        -e POSTGRES_USER=t --name dstest postgres:16-alpine
    DEEPSCAN_TEST_DB_DSN=postgresql://t:t@localhost:55432/deepscan_test \
        uv run pytest tests/test_kruncher_store.py

Otherwise the whole module is skipped.
"""

from __future__ import annotations

import datetime as dt
import os

import pytest

TEST_DSN = os.environ.get("DEEPSCAN_TEST_DB_DSN")
pytestmark = pytest.mark.skipif(not TEST_DSN, reason="DEEPSCAN_TEST_DB_DSN not set")

if TEST_DSN:  # ensure the kruncher targets the test DB before importing it
    os.environ["DEEPSCAN_DB_DSN"] = TEST_DSN

from deepscan_core import Mode, Report, Severity  # noqa: E402
from deepscan_core.models import DedupedFinding  # noqa: E402


def _fake_report(criticals: int = 1) -> Report:
    findings = [
        DedupedFinding(
            severity=Severity.CRITICAL,
            location=f"src/app.py:{i}",
            message="hardcoded secret",
            tools=["gitleaks"],
            rules=["generic-api-key"],
            families=["secret"],
            cwes=["CWE-798"],
            occurrences=1,
            fingerprints=[f"fp{i}"],
        )
        for i in range(criticals)
    ]
    return Report(
        mode=Mode.STATIC,
        target="/tmp/x",
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        duration=1.0,
        tools=[],
        findings=findings,
    )


@pytest.fixture()
def store():
    from deepscan_kruncher import db, store as _store

    db.init_schema()
    with db.connection() as conn:
        conn.execute(
            "TRUNCATE scopes, sources, scan_jobs, job_attempts, scan_results, findings "
            "RESTART IDENTITY CASCADE"
        )
        conn.commit()
    yield _store
    db.close_pool()


@pytest.fixture()
def source(store):
    from deepscan_input_connector_base import KIND_DIRECTORY, DiscoveredSource

    scope = store.upsert_scope(
        name="s", connector="directory", scope_config={"base_path": "/tmp"}
    )
    src = store.upsert_source(
        scope["id"],
        DiscoveredSource(external_id="/tmp/p", kind=KIND_DIRECTORY, name="p", location="/tmp/p"),
    )
    return src


def test_enqueue_claim_persist(store, source):
    job = store.enqueue_scan(source["id"], target_revision="rev1")
    assert job["status"] == "queued"

    claimed = store.claim_job("w1")
    assert claimed and claimed["id"] == job["id"]
    assert claimed["status"] == "running" and claimed["attempt"] == 1

    assert store.claim_job("w2") is None  # nothing left to claim

    store.persist_success(
        claimed, _fake_report(criticals=2), duration=1.5, report_dir="/data/reports/job-1"
    )
    done = store.get_job(job["id"])
    assert done["status"] == "done" and done["completion"] == 100
    # The on-disk report location + summary are recorded on the job row too.
    assert done["report_dir"] == "/data/reports/job-1"
    assert done["summary"] is not None

    refreshed = store.get_source(source["id"])
    assert refreshed["last_scanned_revision"] == "rev1"

    from deepscan_kruncher import db

    res = db.fetchone("SELECT crit, total_findings FROM scan_results WHERE job_id=%s", (job["id"],))
    assert res["crit"] == 2 and res["total_findings"] == 2
    n = db.fetchone("SELECT count(*) AS n FROM findings WHERE source_id=%s", (source["id"],))
    assert n["n"] == 2


def test_discovery_job_writes_and_keeps_reports(store, tmp_path, monkeypatch):
    """A periodic (discovery) scan must write & retain its reports on disk
    (reports/job-<id>) and keep all scanned files under sources/discovery/job-<id>,
    not only persist ASPM rows."""
    monkeypatch.setenv("DEEPSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS", "false")  # scan in place, deterministic

    from deepscan_input_connector_base import KIND_DIRECTORY, DiscoveredSource

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(
        "import os\n\ndef handler(value):\n    os.system('echo ' + value)\n", encoding="utf-8"
    )
    scope = store.upsert_scope(
        name="d", connector="directory", scope_config={"base_path": str(tmp_path)}
    )
    src = store.upsert_source(
        scope["id"],
        DiscoveredSource(
            external_id=str(proj), kind=KIND_DIRECTORY, name="proj", location=str(proj)
        ),
    )
    job = store.enqueue_scan(src["id"], target_revision=None)

    from deepscan_kruncher import worker

    assert worker.process_one("test-disc") is True

    done = store.get_job(job["id"])
    assert done["status"] == "done", done.get("error")

    from deepscan_jobs import config as jc

    rd = jc.job_report_dir(job["id"])
    assert done["report_dir"] == str(rd)
    for name in ("report.json", "report.md", "report.pdf"):
        assert (rd / name).is_file(), f"missing {name}"

    # All scanned files are retained under sources/discovery/job-<id> (a snapshot
    # of the in-place directory), and the operator's real dir is left intact.
    sd = jc.job_source_dir(job["id"], origin="discovery")
    assert sd.is_dir() and (sd / "app.py").is_file()
    assert done["source_path"] == str(sd)
    assert (proj / "app.py").is_file()


def test_manual_queue_preempts_periodic(store, source):
    """A worker draining both queues must take a manual (adhoc) job before a
    queued periodic (discovery) one - the priority guarantee."""
    from deepscan_jobs import store as jobs_store

    periodic = store.enqueue_scan(source["id"], target_revision="rev1")
    manual = jobs_store.create_adhoc_job(
        target_type="path", target="/tmp/x", surface="test"
    )

    first = store.claim_job("w1", origins=("adhoc", "discovery"))
    assert first["id"] == manual["id"] and first["origin"] == "adhoc"

    second = store.claim_job("w2", origins=("adhoc", "discovery"))
    assert second["id"] == periodic["id"] and second["origin"] == "discovery"


def test_reap_stale_manual_job_fails_terminally(store):
    """A stranded manual job is failed terminally (no retry), unlike periodic."""
    from deepscan_jobs import store as jobs_store

    job = jobs_store.create_adhoc_job(
        target_type="path", target="/tmp/x", surface="test", start_running=True
    )
    from deepscan_kruncher import db

    db.execute(
        "UPDATE scan_jobs SET heartbeat_at = now() - interval '1 hour' WHERE id=%s",
        (job["id"],),
    )
    assert store.reap_stale_jobs(lease_seconds=60) == 1
    assert store.get_job(job["id"])["status"] == "failed"


def test_retry_then_dead_letter(store, source):
    job = store.enqueue_scan(source["id"], target_revision="r", max_attempts=2)

    c1 = store.claim_job("w1")
    status1 = store.fail_job(c1, error="boom")
    assert status1 == "queued"  # attempt 1 of 2 -> retry scheduled

    # backoff gates the retry; force it available for the test
    from deepscan_kruncher import db

    db.execute("UPDATE scan_jobs SET available_at = now() WHERE id=%s", (job["id"],))

    c2 = store.claim_job("w1")
    assert c2["attempt"] == 2
    status2 = store.fail_job(c2, error="boom again")
    assert status2 == "dead"  # exhausted -> dead-letter siding

    attempts = store.get_job_attempts(job["id"])
    assert len(attempts) == 2 and all(a["status"] == "failed" for a in attempts)


def test_enqueue_supersedes_open_jobs(store, source):
    first = store.enqueue_scan(source["id"], target_revision="r1")
    store.enqueue_scan(source["id"], target_revision="r2")
    assert store.get_job(first["id"])["status"] == "superseded"


def test_relaunch_dead_job(store, source):
    job = store.enqueue_scan(source["id"], target_revision="r", max_attempts=1)
    c = store.claim_job("w1")
    store.fail_job(c, error="x")
    assert store.get_job(job["id"])["status"] == "dead"

    store.relaunch_job(job["id"])
    again = store.get_job(job["id"])
    assert again["status"] == "queued" and again["attempt"] == 0


def test_reap_stale_running_job(store, source):
    job = store.enqueue_scan(source["id"], target_revision="r")
    store.claim_job("w1")
    from deepscan_kruncher import db

    db.execute(
        "UPDATE scan_jobs SET heartbeat_at = now() - interval '1 hour' WHERE id=%s",
        (job["id"],),
    )
    reaped = store.reap_stale_jobs(lease_seconds=60)
    assert reaped == 1
    # one attempt left was consumed by the claim; re-queued for retry
    assert store.get_job(job["id"])["status"] in ("queued", "dead")
