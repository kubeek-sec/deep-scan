"""Admin REST API (under ``/api``).

Read endpoints feed the dashboard; the few write endpoints relaunch/cancel
jobs and trigger discovery. All data access goes through the kruncher store,
so the admin holds no state of its own.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from deepscan_kruncher import discovery, store
from deepscan_kruncher.connectors import available, get as get_connector
from deepscan_input_connector_base import (
    KIND_DIRECTORY,
    KIND_GIT,
    ConnectorConfigError,
    DiscoveredSource,
)

from . import queries

router = APIRouter(prefix="/api")

_CONNECTOR_EXAMPLES = {
    "git": {"url": "https://github.com/michoo/flanby"},
    "github": {"org": "my-org", "token_env": "GITHUB_TOKEN"},
    "gitlab": {"group": "my-group", "token_env": "GITLAB_TOKEN"},
    "directory": {"base_path": "/data/projects", "layout": "subdirs"},
}


class ScopeBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    connector: str
    config: dict = Field(default_factory=dict)
    families: list[str] = Field(default_factory=list)
    refresh_interval_seconds: int = Field(3600, ge=10)
    rescan_interval_seconds: int = Field(86400, ge=10)
    enabled: bool = True


class SourceBody(BaseModel):
    scope_id: int
    name: str = Field(min_length=1, max_length=200)
    kind: str = KIND_GIT
    location: str = Field(min_length=1)
    default_branch: str | None = None


class SourceUpdateBody(BaseModel):
    name: str | None = None
    location: str | None = None
    default_branch: str | None = None


def _validate_scope(body: ScopeBody) -> None:
    if body.connector not in available():
        raise HTTPException(400, f"Unknown connector. Available: {', '.join(available())}")
    try:
        get_connector(body.connector).validate_config(body.config)
    except ConnectorConfigError as exc:
        raise HTTPException(400, f"Invalid connector config: {exc}") from None


@router.get("/overview")
def overview() -> dict:
    return {
        "queue": store.queue_depth(),               # both queues combined
        "queues": store.queue_depth_by_origin(),    # split: discovery vs adhoc
        "posture": queries.posture_totals(),
        "scopes": queries.scope_inventory(),
    }


@router.get("/posture")
def posture() -> dict:
    return {
        "totals": queries.posture_totals(),
        "by_scope": queries.posture_by_scope(),
        "top_sources": queries.top_risky_sources(),
    }


@router.get("/trends")
def trends(window: str = Query("1y", pattern="^(3m|1y)$")) -> dict:
    return {"window": window, "series": queries.trend(window)}


@router.get("/connectors")
def connectors() -> dict:
    return {"available": available(), "examples": _CONNECTOR_EXAMPLES}


@router.get("/scopes")
def scopes() -> list[dict]:
    return store.list_scopes()


@router.post("/scopes", status_code=201)
def create_scope(body: ScopeBody) -> dict:
    _validate_scope(body)
    if store.get_scope_by_name(body.name):
        raise HTTPException(409, f"A scope named {body.name!r} already exists.")
    return store.upsert_scope(
        name=body.name,
        connector=body.connector,
        scope_config=body.config,
        enabled=body.enabled,
        refresh_interval_seconds=body.refresh_interval_seconds,
        rescan_interval_seconds=body.rescan_interval_seconds,
        families=body.families,
    )


@router.put("/scopes/{scope_id}")
def update_scope(scope_id: int, body: ScopeBody) -> dict:
    if store.get_scope(scope_id) is None:
        raise HTTPException(404, "Unknown scope.")
    _validate_scope(body)
    clash = store.get_scope_by_name(body.name)
    if clash and clash["id"] != scope_id:
        raise HTTPException(409, f"Another scope already uses the name {body.name!r}.")
    row = store.update_scope(
        scope_id,
        name=body.name,
        connector=body.connector,
        scope_config=body.config,
        enabled=body.enabled,
        refresh_interval_seconds=body.refresh_interval_seconds,
        rescan_interval_seconds=body.rescan_interval_seconds,
        families=body.families,
    )
    return row


@router.delete("/scopes/{scope_id}")
def delete_scope(scope_id: int) -> dict:
    if store.get_scope(scope_id) is None:
        raise HTTPException(404, "Unknown scope.")
    store.delete_scope(scope_id)
    return {"deleted": scope_id}


@router.post("/scopes/{scope_id}/enabled")
def set_scope_enabled(scope_id: int, enabled: bool = Query(...)) -> dict:
    if store.get_scope(scope_id) is None:
        raise HTTPException(404, "Unknown scope.")
    store.set_scope_enabled(scope_id, enabled)
    return {"id": scope_id, "enabled": enabled}


@router.post("/scopes/{scope_id}/discover")
def discover_scope(scope_id: int) -> dict:
    scope = store.get_scope(scope_id)
    if scope is None:
        raise HTTPException(404, "Unknown scope.")
    outcome = discovery.refresh_scope(scope)
    return {
        "discovered": outcome.discovered,
        "deactivated": outcome.deactivated,
        "error": outcome.error,
    }


@router.get("/sources")
def sources(
    scope_id: int | None = None,
    q: str | None = None,
    risk: str | None = Query(None, pattern="^(critical|high|clean|unscanned)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    include_inactive: bool = False,
) -> dict:
    return queries.sources_page(scope_id, q, risk, limit, offset, include_inactive)


@router.get("/sources/{source_id}")
def source_detail(source_id: int) -> dict:
    src = store.get_source(source_id)
    if src is None:
        raise HTTPException(404, "Unknown source.")
    return {
        "source": src,
        "history": queries.source_history(source_id),
        "findings": queries.latest_findings(source_id),
        "jobs": store.list_jobs(source_id=source_id, limit=20),
    }


@router.post("/sources", status_code=201)
def create_source(body: SourceBody) -> dict:
    if store.get_scope(body.scope_id) is None:
        raise HTTPException(404, "Unknown scope.")
    if body.kind not in (KIND_GIT, KIND_DIRECTORY):
        raise HTTPException(400, "kind must be 'git' or 'directory'.")
    source = DiscoveredSource(
        external_id=body.location,
        kind=body.kind,
        name=body.name,
        location=body.location,
        default_branch=body.default_branch,
        metadata={"manual": True},
    )
    return store.upsert_source(body.scope_id, source)


@router.put("/sources/{source_id}")
def update_source(source_id: int, body: SourceUpdateBody) -> dict:
    if store.get_source(source_id) is None:
        raise HTTPException(404, "Unknown source.")
    row = store.update_source(
        source_id,
        name=body.name,
        location=body.location,
        default_branch=body.default_branch,
    )
    return row


@router.post("/sources/{source_id}/active")
def set_source_active(source_id: int, active: bool = Query(...)) -> dict:
    if store.get_source(source_id) is None:
        raise HTTPException(404, "Unknown source.")
    store.set_source_active(source_id, active)
    return {"id": source_id, "active": active}


@router.delete("/sources/{source_id}")
def delete_source(source_id: int) -> dict:
    if store.get_source(source_id) is None:
        raise HTTPException(404, "Unknown source.")
    store.delete_source(source_id)
    return {"deleted": source_id}


@router.post("/sources/{source_id}/scan")
def scan_source_now(source_id: int) -> dict:
    src = store.get_source(source_id)
    if src is None:
        raise HTTPException(404, "Unknown source.")
    job = store.enqueue_scan(
        source_id, target_revision=None, branch=src["default_branch"], priority=10
    )
    return {"job_id": job["id"], "status": "queued"}


@router.get("/jobs")
def jobs(
    status: str | None = None,
    source_id: int | None = None,
    origin: str | None = Query(None, pattern="^(discovery|adhoc)$"),
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict]:
    """Jobs across both queues by default. ``origin=discovery`` shows only the
    periodic queue, ``origin=adhoc`` only the manual (API/MCP) queue."""
    return store.list_jobs(
        status=status, source_id=source_id, origin=origin, limit=limit
    )


@router.get("/jobs/{job_id}")
def job_detail(job_id: int) -> dict:
    job = store.get_job(job_id)
    if job is None:
        raise HTTPException(404, "Unknown job.")
    return {
        "job": job,
        "attempts": store.get_job_attempts(job_id),
        "report": queries.job_report(job),
    }


@router.post("/jobs/{job_id}/relaunch")
def relaunch(job_id: int) -> dict:
    row = store.relaunch_job(job_id)
    if row is None:
        raise HTTPException(409, "Job is not in a relaunchable state.")
    return {"status": "queued", "id": job_id}


@router.post("/jobs/{job_id}/cancel")
def cancel(job_id: int) -> dict:
    row = store.cancel_job(job_id)
    if row is None:
        raise HTTPException(409, "Job is not in a cancellable state.")
    if row.get("prev_status") == "running":
        # The worker holding the lease polls the status and aborts cooperatively;
        # it stops within a few seconds (sooner than the analysis taint budget).
        return {
            "status": "cancelling",
            "id": job_id,
            "message": "Running job flagged cancelled - the worker will stop it shortly.",
        }
    return {"status": "cancelled", "id": job_id}
