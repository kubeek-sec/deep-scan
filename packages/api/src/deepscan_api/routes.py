"""REST endpoints (all under ``/api``).

Submission endpoints validate the target and parameters up front and return
400 with a clear message; the actual work (clone, scan, report) happens in the
shared ``deepscan_jobs`` worker pool. Jobs are ``origin='adhoc'`` rows in the
shared Postgres store, so scans submitted here (and via the MCP server) all
show up in the same dashboard.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from deepscan_core import Family, Mode, install, registry
from deepscan_core.registry import UnknownScannerError
from deepscan_core.reporting import ALL_FORMATS, file_suffix, report_filename
from deepscan_core.targets import TargetError
from deepscan_core.validation import (
    ScanTargetError,
    resolve_scan_dir,
    validate_target_url,
)
from deepscan_jobs import config as jobs_config
from deepscan_jobs import store as jobs_store
from deepscan_jobs import uploads as jobs_uploads
from deepscan_jobs.models import ADHOC_TARGET_TYPES

from . import pipelines, settings

router = APIRouter(prefix="/api")

_UPLOAD_CHUNK = 1024 * 1024
_REPORT_MEDIA_TYPES = {
    "json": "application/json",
    "md": "text/markdown",
    "html": "text/html",
    "sarif": "application/sarif+json",
    "junit": "application/xml",
    "pdf": "application/pdf",
}


class ScanRequest(BaseModel):
    target_type: str
    target: str
    mode: str | None = None
    families: list[str] | None = None
    scanners: list[str] | None = None


class CapabilitySelection(BaseModel):
    key: str
    # Empty/omitted means "every tool in this capability"; a subset narrows it.
    scanners: list[str] = []


class PipelineRequest(BaseModel):
    """A CI-template wizard selection (see ``deepscan_api.pipelines``)."""

    platform: str
    capabilities: list[CapabilitySelection] = []
    formats: list[str] | None = None
    fail_on: str | None = pipelines.DEFAULT_FAIL_ON
    gate: str = "fail"
    image: str | None = None
    target: str | None = None
    reports_dir: str | None = None
    config_dir: str | None = None
    env: dict[str, str] | None = None


def _bad_request(message: str) -> HTTPException:
    return HTTPException(status_code=400, detail=message)


def _job_id(raw: str) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="Unknown scan id.") from None


def _reports_dir(job_id: int) -> Path:
    return jobs_config.job_report_dir(job_id)


def _graph_html_path(job: dict[str, Any]) -> Path:
    """The interactive code-graph viewer the ``analysis`` scanner writes under
    the scan's raw dir (only present when that scanner ran and built a graph)."""
    base = Path(job["report_dir"]) if job.get("report_dir") else _reports_dir(job["id"])
    return base / "raw" / "graph.html"


def _validate_params(
    mode: str | None, families: list[str] | None, scanners: list[str] | None
) -> tuple[str | None, list[str], list[str]]:
    """Normalize mode/families/scanners; raise 400 on unknown values."""
    if mode:
        try:
            mode = Mode(mode.strip().lower()).value
        except ValueError:
            valid = ", ".join(m.value for m in Mode)
            raise _bad_request(f"Unknown mode {mode!r}. Available: {valid}") from None
    checked_families: list[str] = []
    for raw in families or []:
        try:
            checked_families.append(Family(raw.strip().lower()).value)
        except ValueError:
            valid = ", ".join(f.value for f in Family)
            raise _bad_request(f"Unknown family {raw!r}. Available: {valid}") from None
    checked_scanners: list[str] = []
    for raw in scanners or []:
        try:
            checked_scanners.append(registry.get(raw.strip()).name)
        except UnknownScannerError as exc:
            raise _bad_request(str(exc)) from None
    return mode, checked_families, checked_scanners


def _validate_git_url(raw: str) -> None:
    """Shape check only - the clone happens in the worker."""
    raw = (raw or "").strip()
    parts = urlsplit(raw)
    if not raw or raw.startswith("-"):
        raise TargetError("Git URL may not be empty or start with '-'.")
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise TargetError("Git target must be an http(s) URL with a host.")


def _validate_target(target_type: str, target: str) -> None:
    try:
        if target_type == "url":
            validate_target_url(target, allow_private=settings.allow_private_targets())
        elif target_type == "git":
            _validate_git_url(target)
        elif target_type == "path":
            if not settings.allow_local_paths():
                raise ScanTargetError(
                    "Local path targets are disabled "
                    "(DEEPSCAN_API_ALLOW_LOCAL_PATHS=false)."
                )
            resolve_scan_dir(target)
    except (ScanTargetError, TargetError) as exc:
        raise _bad_request(str(exc)) from None


def _split_csv(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    return [item.strip() for item in raw.split(",") if item.strip()]


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/scanners")
async def scanners() -> list[dict[str, str]]:
    return registry.describe()


@router.get("/tools")
async def tools() -> list[dict[str, Any]]:
    return [dataclasses.asdict(s) for s in install.status_all()]


@router.get("/pipeline/options")
async def pipeline_options() -> dict[str, Any]:
    """Everything the CI-template wizard needs: supported platforms, the
    capability → tool catalog (from the live scanner registry), report formats,
    severities and gates."""
    return pipelines.options()


@router.post("/pipeline/generate")
async def pipeline_generate(payload: PipelineRequest) -> dict[str, Any]:
    """Render a ready-to-commit pipeline file from a wizard selection."""
    try:
        return pipelines.generate(
            platform=payload.platform,
            capabilities=[c.model_dump() for c in payload.capabilities],
            formats=payload.formats,
            fail_on=payload.fail_on,
            gate=payload.gate,
            image=payload.image,
            target=payload.target,
            reports_dir=payload.reports_dir,
            config_dir=payload.config_dir,
            env=payload.env,
        )
    except pipelines.PipelineError as exc:
        raise _bad_request(str(exc)) from None


@router.post("/scans", status_code=201)
async def submit_scan(payload: ScanRequest, request: Request) -> dict[str, Any]:
    target_type = payload.target_type.strip().lower()
    if target_type == "zip":
        raise _bad_request("Use POST /api/scans/zip (multipart) for zip targets.")
    if target_type not in ADHOC_TARGET_TYPES:
        raise _bad_request(
            f"Unknown target_type {payload.target_type!r}. "
            f"Available: {', '.join(ADHOC_TARGET_TYPES)}"
        )
    mode, families, scanners = _validate_params(
        payload.mode, payload.families, payload.scanners
    )
    _validate_target(target_type, payload.target)
    job = jobs_store.create_adhoc_job(
        target_type=target_type,
        target=payload.target.strip(),
        mode=mode,
        families=families,
        scanners=scanners,
        surface="api",
    )
    return {"id": job["id"], "status": job["status"]}


@router.post("/scans/zip", status_code=201)
async def submit_zip_scan(
    request: Request,
    file: UploadFile = File(...),
    mode: str | None = Form(None),
    families: str | None = Form(None),
    scanners: str | None = Form(None),
) -> dict[str, Any]:
    checked_mode, checked_families, checked_scanners = _validate_params(
        mode, _split_csv(families), _split_csv(scanners)
    )

    fd, tmp_name = tempfile.mkstemp(suffix=".zip", prefix="deepscan-upload-")
    try:
        size = 0
        with os.fdopen(fd, "wb") as tmp:
            while chunk := await file.read(_UPLOAD_CHUNK):
                size += len(chunk)
                if size > settings.MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Upload exceeds the 200 MiB limit.",
                    )
                tmp.write(chunk)
        if size == 0:
            raise _bad_request("Uploaded file is empty.")
        try:
            upload = await asyncio.to_thread(
                jobs_uploads.stage_zip, tmp_name, file.filename
            )
        except TargetError as exc:
            raise _bad_request(str(exc)) from None
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass

    job = jobs_store.create_adhoc_job(
        target_type="zip",
        target=upload["path"],
        mode=checked_mode,
        families=checked_families,
        scanners=checked_scanners,
        surface="api",
        upload_id=upload["id"],
    )
    return {"id": job["id"], "status": job["status"]}


@router.get("/scans")
async def list_scans(
    request: Request,
    response: Response,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    """One page of manual (adhoc) scans, newest first. The body stays a plain
    list (stable contract); the total row count for pagination is returned in the
    ``X-Total-Count`` header."""
    response.headers["X-Total-Count"] = str(jobs_store.count_jobs(origin="adhoc"))
    return jobs_store.list_jobs(origin="adhoc", limit=limit, offset=offset)


@router.get("/scans/{job_id}")
async def get_scan(job_id: str, request: Request) -> dict[str, Any]:
    job = jobs_store.get_job(_job_id(job_id))
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    # Cheap existence stat so the UI knows whether to offer the "Code graph" tab.
    job["has_graph"] = _graph_html_path(job).is_file()
    return job


@router.get("/scans/{job_id}/report")
async def get_report(
    job_id: str, request: Request, format: str = Query("json")
) -> FileResponse:
    if format not in ALL_FORMATS:
        raise _bad_request(
            f"Unknown report format {format!r}. Available: {', '.join(ALL_FORMATS)}"
        )
    job = jobs_store.get_job(_job_id(job_id))
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    if job["status"] != "done" or not job["report_dir"]:
        raise HTTPException(
            status_code=409,
            detail=f"Report not available: job status is {job['status']!r}.",
        )
    path = Path(job["report_dir"]) / report_filename(format)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report file is missing on disk.")
    return FileResponse(
        path,
        media_type=_REPORT_MEDIA_TYPES[format],
        filename=f"deepscan-{job_id}.{file_suffix(format)}",
        content_disposition_type="inline",
    )


@router.get("/scans/{job_id}/graph")
async def get_graph(job_id: str, request: Request) -> FileResponse:
    """Serve the standalone interactive code-graph viewer (``graph.html``).

    Loaded on demand (the dashboard only fetches it when the user opens the
    graph sub-tab), since the embedded graph can be large."""
    job = jobs_store.get_job(_job_id(job_id))
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    path = _graph_html_path(job)
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="No code graph - the analysis scanner did not build one for this scan.",
        )
    return FileResponse(path, media_type="text/html", content_disposition_type="inline")


_TRIAGE_FORMATS = ("json", "md", "html")


@router.get("/scans/{job_id}/triage")
async def get_triage(
    job_id: str, request: Request, format: str = Query("md")
) -> FileResponse:
    """Fetch the ai-analysis triage report (only present if the ai-analysis
    scanner ran for this scan)."""
    if format not in _TRIAGE_FORMATS:
        raise _bad_request(
            f"Unknown triage format {format!r}. Available: {', '.join(_TRIAGE_FORMATS)}"
        )
    job = jobs_store.get_job(_job_id(job_id))
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    if job["status"] != "done" or not job["report_dir"]:
        raise HTTPException(
            status_code=409,
            detail=f"Triage not available: job status is {job['status']!r}.",
        )
    path = Path(job["report_dir"]) / f"triage.{format}"
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="No triage report - the ai-analysis scanner did not run for this scan.",
        )
    return FileResponse(
        path,
        media_type=_REPORT_MEDIA_TYPES[format],
        filename=f"deepscan-triage-{job_id}.{format}",
        content_disposition_type="inline",
    )


@router.delete("/scans/{job_id}", status_code=204)
async def delete_scan(job_id: str, request: Request) -> Response:
    jid = _job_id(job_id)
    job = jobs_store.get_job(jid)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    if job["status"] == "running":
        raise HTTPException(status_code=409, detail="Cannot delete a running scan.")
    if job["report_dir"]:
        shutil.rmtree(job["report_dir"], ignore_errors=True)
    shutil.rmtree(_reports_dir(jid), ignore_errors=True)
    shutil.rmtree(
        jobs_config.job_source_dir(jid, origin=job["origin"], surface=job.get("surface")),
        ignore_errors=True,
    )
    # A zip job's analyzed files live in the shared upload dir - remove it and its
    # row too (an explicit per-scan delete is the cleanup path for retained files).
    if job.get("upload_id"):
        shutil.rmtree(jobs_uploads.uploads_dir() / job["upload_id"], ignore_errors=True)
        jobs_uploads.delete_upload(job["upload_id"])
    jobs_store.delete_job(jid)
    return Response(status_code=204)
