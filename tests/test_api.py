"""Integration test for the REST API over the shared Postgres job store.

Runs only with a throwaway Postgres in DEEPSCAN_TEST_DB_DSN (see
test_kruncher_store.py for how to start one); otherwise skipped.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

TEST_DSN = os.environ.get("DEEPSCAN_TEST_DB_DSN")
pytestmark = pytest.mark.skipif(not TEST_DSN, reason="DEEPSCAN_TEST_DB_DSN not set")

if TEST_DSN:
    os.environ["DEEPSCAN_DB_DSN"] = TEST_DSN


@pytest.fixture()
def client(tmp_path):
    os.environ["DEEPSCAN_DATA_DIR"] = str(tmp_path / "data")
    from fastapi.testclient import TestClient

    from deepscan_jobs import db
    from deepscan_api.main import create_app

    db.init_schema()
    with db.connection() as conn:
        conn.execute(
            "TRUNCATE scan_jobs, job_attempts, scan_results, findings, uploads "
            "RESTART IDENTITY CASCADE"
        )
        conn.commit()
    with TestClient(create_app()) as c:
        yield c
    db.close_pool()


def _wait_done(client, job_id, timeout=120):
    # The API is a submitter, not an executor: it enqueues a manual (adhoc) job
    # and the kruncher worker fleet runs it. Drive a worker here (it now drains
    # both the manual and periodic queues) to process the queued scan. Run it in
    # its own thread - mirroring the separate worker process - so its
    # asyncio.run() gets a fresh loop and never collides with an event loop a
    # prior test may have left running on the main thread (e.g. Playwright's).
    import threading

    from deepscan_kruncher import worker

    stop = threading.Event()

    def _pump() -> None:
        while not stop.is_set():
            if not worker.process_one("test-worker"):
                time.sleep(0.05)

    pump = threading.Thread(target=_pump, name="test-kruncher", daemon=True)
    pump.start()
    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = client.get(f"/api/scans/{job_id}").json()
            if job["status"] in ("done", "failed", "dead"):
                return job
            time.sleep(0.1)
        raise AssertionError("scan did not finish in time")
    finally:
        stop.set()
        pump.join(timeout=5)


def test_submit_path_scan_end_to_end(client, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "main.py").write_text("print('hello')\n", encoding="utf-8")

    resp = client.post(
        "/api/scans",
        json={"target_type": "path", "target": str(proj), "scanners": ["analysis"]},
    )
    assert resp.status_code == 201, resp.text
    job_id = resp.json()["id"]
    assert resp.json()["status"] == "queued"

    job = _wait_done(client, job_id)
    assert job["status"] == "done", job
    assert job["summary"] is not None
    assert job["report_dir"]

    # Source location + content fingerprint recorded; a local 'path' target is
    # referenced in place.
    assert job["source_path"]
    assert Path(job["source_path"]).resolve() == proj.resolve()
    assert job["fingerprint"] and job["fingerprint"].startswith("sha512:")
    assert proj.is_dir()

    # listed in the (adhoc) dashboard feed
    listed = client.get("/api/scans").json()
    assert any(j["id"] == job_id for j in listed)

    # reports fetchable
    md = client.get(f"/api/scans/{job_id}/report?format=md")
    assert md.status_code == 200 and md.text
    js = client.get(f"/api/scans/{job_id}/report?format=json")
    assert js.status_code == 200
    pdf = client.get(f"/api/scans/{job_id}/report?format=pdf")
    assert pdf.status_code == 200
    assert pdf.content[:5] == b"%PDF-"
    assert "application/pdf" in pdf.headers["content-type"]

    # delete cleans up - but never the user's in-place 'path' source.
    assert client.delete(f"/api/scans/{job_id}").status_code == 204
    assert client.get(f"/api/scans/{job_id}").status_code == 404
    assert proj.is_dir()


def test_unknown_id_is_404(client):
    assert client.get("/api/scans/999999").status_code == 404
    # non-numeric id is also a clean 404, not a 500
    assert client.get("/api/scans/not-an-int").status_code == 404


def test_zip_scan_end_to_end(client, tmp_path):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.py", "print('hi')\n")
    buf.seek(0)

    resp = client.post(
        "/api/scans/zip",
        files={"file": ("proj.zip", buf.getvalue(), "application/zip")},
        data={"scanners": "analysis"},
    )
    assert resp.status_code == 201, resp.text
    job = _wait_done(client, resp.json()["id"])
    assert job["status"] == "done", job

    # Provenance recorded; the extracted upload is retained per-job under
    # sources/<surface>/job-<id> (api here), AND its raw uploads/ staging is kept.
    assert job["upload_id"]
    assert job["fingerprint"] and job["fingerprint"].startswith("sha512:")
    sp = Path(job["source_path"])
    assert sp.is_dir() and (sp / "main.py").is_file()
    assert sp.parent.name == "api" and sp.parent.parent.name == "sources"
    uploaded = Path(os.environ["DEEPSCAN_DATA_DIR"]) / "uploads" / job["upload_id"]
    assert uploaded.is_dir() and (uploaded / "main.py").is_file()

    # Regression: a second scan of the same upload_id succeeds. The old code
    # deleted the extracted dir after the first scan, which broke re-scans.
    from deepscan_jobs import store, uploads

    job2 = store.create_adhoc_job(
        target_type="zip", target=str(sp), scanners=["analysis"],
        surface="test", upload_id=job["upload_id"],
    )
    assert _wait_done(client, job2["id"])["status"] == "done"

    # Deleting a zip scan removes its retained upload dir + row.
    assert client.delete(f"/api/scans/{job['id']}").status_code == 204
    assert not sp.exists()
    assert uploads.get_upload(job["upload_id"]) is None
