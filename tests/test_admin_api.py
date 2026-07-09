"""Integration tests for the admin REST API (scope/source CRUD + posture).

Runs only with a throwaway Postgres in DEEPSCAN_TEST_DB_DSN (see
test_kruncher_store.py for how to start one).
"""

from __future__ import annotations

import os

import pytest

TEST_DSN = os.environ.get("DEEPSCAN_TEST_DB_DSN")
pytestmark = pytest.mark.skipif(not TEST_DSN, reason="DEEPSCAN_TEST_DB_DSN not set")

if TEST_DSN:
    os.environ["DEEPSCAN_DB_DSN"] = TEST_DSN


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from deepscan_kruncher import db
    from deepscan_kruncher_admin.main import create_app

    db.init_schema()
    with db.connection() as conn:
        conn.execute(
            "TRUNCATE scopes, sources, scan_jobs, job_attempts, scan_results, findings "
            "RESTART IDENTITY CASCADE"
        )
        conn.commit()
    return TestClient(create_app())


def test_connectors_listed(client):
    body = client.get("/api/connectors").json()
    assert {"directory", "github", "gitlab"} <= set(body["available"])
    assert "directory" in body["examples"]


def test_scope_crud(client):
    # create
    r = client.post(
        "/api/scopes",
        json={"name": "local", "connector": "directory", "config": {"base_path": "/tmp"}},
    )
    assert r.status_code == 201
    sid = r.json()["id"]

    # invalid connector config -> 400
    assert client.post(
        "/api/scopes", json={"name": "x", "connector": "github", "config": {}}
    ).status_code == 400
    # duplicate name -> 409
    assert client.post(
        "/api/scopes",
        json={"name": "local", "connector": "directory", "config": {"base_path": "/tmp"}},
    ).status_code == 409

    # update (rename + disable)
    r = client.put(
        f"/api/scopes/{sid}",
        json={"name": "renamed", "connector": "directory",
              "config": {"base_path": "/tmp"}, "enabled": False},
    )
    assert r.status_code == 200 and r.json()["name"] == "renamed" and r.json()["enabled"] is False

    # re-enable via toggle
    assert client.post(f"/api/scopes/{sid}/enabled", params={"enabled": True}).status_code == 200

    # delete
    assert client.delete(f"/api/scopes/{sid}").status_code == 200
    assert client.get("/api/scopes").json() == []
    assert client.delete(f"/api/scopes/{sid}").status_code == 404


def test_source_crud_and_scan(client):
    sid = client.post(
        "/api/scopes",
        json={"name": "local", "connector": "directory", "config": {"base_path": "/tmp"}},
    ).json()["id"]

    r = client.post(
        "/api/sources",
        json={"scope_id": sid, "name": "svc", "kind": "directory", "location": "/tmp"},
    )
    assert r.status_code == 201
    src = r.json()["id"]

    assert client.put(f"/api/sources/{src}", json={"name": "svc2"}).json()["name"] == "svc2"

    # scan now enqueues a job
    r = client.post(f"/api/sources/{src}/scan")
    assert r.status_code == 200 and r.json()["status"] == "queued"

    # deactivate -> hidden by default, visible with include_inactive
    client.post(f"/api/sources/{src}/active", params={"active": False})
    assert not any(s["id"] == src for s in client.get("/api/sources").json()["items"])
    inactive = client.get("/api/sources", params={"include_inactive": True}).json()["items"]
    assert any(s["id"] == src and s["active"] is False for s in inactive)

    assert client.delete(f"/api/sources/{src}").status_code == 200
    assert client.delete(f"/api/sources/{src}").status_code == 404


def test_static_index_served(client):
    # The single-page UI and its assets are served by the same app.
    assert client.get("/").status_code == 200
    assert "kruncher admin" in client.get("/").text.lower()
