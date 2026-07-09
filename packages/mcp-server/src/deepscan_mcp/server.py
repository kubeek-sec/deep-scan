"""Deep Scan MCP server.

Exposes the shared scanner library to agents and IDEs over MCP. The tools map
one-to-one onto the library's selection model:

- ``static_scan`` / ``dynamic_scan`` - run every applicable scanner, deduped
- ``scan_family`` - one family (sast, sca, secret, iac, license, pipeline, dast)
- ``scan_with`` - a single named scanner
- ``list_graph_questions`` / ``query_graph`` - query the analysis code graph for
  precise AppSec questions (unsanitized sources, critical functions, endpoints →
  sink/taint, paths to critical, external deps, attack paths, blast radius)
- ``list_scanners`` / ``tool_status`` / ``install_tool`` - introspection & setup

Every scan becomes a job in the shared Postgres store (``deepscan_jobs``) and the
relevant collected data is returned inline so an agent gets an immediately
readable result (the job also shows up in the web dashboard):

- a single scanner (``scan_with``) returns that scanner's report;
- a family / full scan (``scan_family``, ``static_scan``, ``dynamic_scan``)
  returns the final consolidated report plus the code-graph report (``graph.json``,
  when the ``analysis`` scanner ran and built it).

**Where the scan runs.** By default the deployed http transport hands the job to
the shared **kruncher worker fleet** (the same fleet that runs periodic scans, so
the API/MCP and the scheduler never compete for in-process CPU) and polls for the
result, reading the report off the shared ``/data`` volume. Local stdio runs the
job inline (an IDE-launched server has no fleet). Override with
``DEEPSCAN_MCP_RUN_VIA_KRUNCHER=true|false``.

How the project files reach the server depends on the transport:

- **stdio** (server launched locally by the IDE/agent): pass ``project_dir`` -
  just the path; the server reads it directly off the local filesystem.
- **streamable-http** (server possibly remote): upload the project first
  (``deepscan_mcp.client.upload_project`` → ``upload_id``) and pass ``upload_id``.
  A server-side ``project_dir`` is only honored when
  ``DEEPSCAN_MCP_ALLOW_LOCAL_PATHS`` is set.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from deepscan_core import Family, Mode, install, registry
from deepscan_core.analysis import QUESTIONS, answer, security_payload
from deepscan_core.config import get as _config_get
from deepscan_core.reporting import render, render_triage_console
from deepscan_core.targets import TargetError
from deepscan_core.validation import ScanTargetError, resolve_scan_dir
from deepscan_jobs import config as jobs_config
from deepscan_jobs import store as jobs_store
from deepscan_jobs import uploads as jobs_uploads
from deepscan_jobs import worker as jobs_worker
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("deepscan")

# The active transport, set in main(). Tools branch on it to decide whether a
# server-side path is acceptable (stdio: always; http: only when allowed).
_TRANSPORT = "stdio"

_MAX_UPLOAD_BYTES = 200 * 1024 * 1024

# Cache the (expensive) security-graph payload per project so repeated graph
# questions in a session are instant; the graphoofy extraction is also cached on
# disk under a per-project dir.
_payload_cache: dict[str, Any] = {}


def _allow_local_paths() -> bool:
    """Whether a server-side ``project_dir`` is honored over the http transport.

    Always true for stdio (the server is local); for http it is gated by
    ``DEEPSCAN_MCP_ALLOW_LOCAL_PATHS`` (off by default)."""
    if _TRANSPORT == "stdio":
        return True
    return (_config_get("DEEPSCAN_MCP_ALLOW_LOCAL_PATHS") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _graph_payload(project_dir: str, refresh: bool = False):
    target = resolve_scan_dir(project_dir)
    key = str(target)
    if refresh or key not in _payload_cache:
        import hashlib

        cache = Path(tempfile.gettempdir()) / "deepscan-graphquery" / hashlib.sha256(
            key.encode()).hexdigest()[:16]
        cache.mkdir(parents=True, exist_ok=True)
        _payload_cache[key] = security_payload(target, cache)
    return _payload_cache[key]


def _families(values: list[str] | None) -> list[Family] | None:
    if not values:
        return None
    try:
        return [Family(v.strip().lower()) for v in values]
    except ValueError as exc:
        raise ValueError(
            f"Unknown family. Choose from: {', '.join(f.value for f in Family)}"
        ) from exc


def _read_graph_report(report_dir: Path) -> str | None:
    """The code-graph report (``graph.json``) for a family / full scan.

    The ``analysis`` scanner writes ``graph.json`` under the scan's ``raw`` dir
    when it builds the code graph. Returns the formatted report, or ``None`` when
    no graph was produced (e.g. a family scan without the ``analysis`` scanner, or
    a dynamic/URL target where there is no code to graph)."""
    graph_json = report_dir / "raw" / "graph.json"
    if not graph_json.exists():
        return None
    content = graph_json.read_text(encoding="utf-8")
    return (
        f"## Graph report\n\n"
        f"Code graph written to {graph_json}.\n\n"
        f"```json\n{content}\n```"
    )


def _resolve_target(
    *,
    mode: Mode,
    project_dir: str | None,
    upload_id: str | None,
    target_url: str | None,
) -> tuple[str, str]:
    """Resolve (target_type, target) for an ad-hoc job from the tool inputs and
    the active transport. Raises ``ValueError`` with actionable guidance."""
    if mode == Mode.DYNAMIC:
        if not target_url:
            raise ValueError("A target URL is required for a dynamic scan.")
        return "url", target_url
    # Static scan - needs a directory.
    if upload_id:
        path = jobs_uploads.resolve_upload(upload_id)
        if not path:
            raise ValueError(
                f"Unknown upload_id {upload_id!r}. Upload the project first with "
                "deepscan_mcp.client.upload_project()."
            )
        # An uploaded, already-extracted dir: treat as a staged 'zip' (cleaned up).
        return "zip", path
    if project_dir:
        if not _allow_local_paths():
            raise ValueError(
                "Server-side paths are disabled for the http transport. Upload the "
                "project with deepscan_mcp.client.upload_project() and pass upload_id, "
                "or set DEEPSCAN_MCP_ALLOW_LOCAL_PATHS=1 on the server."
            )
        return "path", project_dir
    raise ValueError(
        "Provide a project_dir (stdio) or an upload_id (http upload, see "
        "deepscan_mcp.client.upload_project)."
    )


def _run_via_kruncher() -> bool:
    """Whether to hand scans to the kruncher fleet (vs. run them inline).

    Default: the deployed http transport routes to the fleet (production runs a
    kruncher fleet sharing the job store + ``/data`` volume); local stdio runs
    inline (an IDE-launched server usually has no fleet). Override with
    ``DEEPSCAN_MCP_RUN_VIA_KRUNCHER=true|false``."""
    raw = (_config_get("DEEPSCAN_MCP_RUN_VIA_KRUNCHER") or "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return _TRANSPORT != "stdio"


def _scan_timeout(default: int = 1800) -> int:
    """Max seconds to wait for the fleet to finish a queued scan."""
    raw = _config_get("DEEPSCAN_MCP_SCAN_TIMEOUT")
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return default


_TERMINAL = {"done", "failed", "dead", "cancelled", "superseded"}


async def _await_job(job_id: int, *, timeout: int, poll: float = 2.0) -> dict[str, Any] | None:
    """Poll a queued job until it reaches a terminal state or ``timeout``.

    Returns the latest job row (which may still be queued/running on timeout), or
    ``None`` if the job disappeared."""
    deadline = time.monotonic() + timeout
    while True:
        job = await asyncio.to_thread(jobs_store.get_job, job_id)
        if job is None or job["status"] in _TERMINAL:
            return job
        if time.monotonic() >= deadline:
            return job
        await asyncio.sleep(poll)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _source_line(source_path: str | None, upload_id: str | None) -> str:
    """One-line note on where the analyzed files are retained (empty if unknown)."""
    if not source_path:
        return ""
    suffix = f" (upload_id {upload_id})" if upload_id else ""
    return f"Source files retained at {source_path}{suffix}.\n\n"


def _format_report_from_disk(job: dict[str, Any], *, with_graph_report: bool) -> str:
    """Build the tool output for a fleet-run scan from the report files the
    worker wrote to the shared ``/data`` volume."""
    jid = job["id"]
    report_dir = jobs_config.data_dir() / "reports" / f"job-{jid}"
    summary = job.get("summary") or {}
    header = (
        f"Report written to {report_dir} (json/md/html/sarif/junit/pdf). Job #{jid}. "
        f"Summary: {json.dumps(summary, default=str)}\n\n"
    )
    header += _source_line(job.get("source_path"), job.get("upload_id"))
    body = _read_text(report_dir / "report.md") or "_No markdown report on disk._"
    triage_md = _read_text(report_dir / "triage.md")
    if triage_md:
        header += "Triage report (json/md/html) also written.\n\n"
        body += "\n\n## Triage\n\n" + triage_md.strip()
    out = header + body
    if with_graph_report:
        graph = _read_graph_report(report_dir)
        out += "\n\n" + (graph or (
            "## Graph report\n\n"
            "_No code graph available - the `analysis` scanner did not run for "
            "this scan._"
        ))
    return out


async def _run_job(
    *,
    mode: Mode,
    project_dir: str | None = None,
    upload_id: str | None = None,
    target_url: str | None = None,
    families: list[Family] | None = None,
    scanners: list[str] | None = None,
    with_graph_report: bool = True,
) -> str:
    """Create an ad-hoc job and return its report (plus the graph report for
    family/full scans). Runs on the kruncher fleet or inline per
    :func:`_run_via_kruncher`."""
    target_type, target = _resolve_target(
        mode=mode, project_dir=project_dir, upload_id=upload_id, target_url=target_url
    )
    fam_values = [f.value for f in families] if families else None

    if _run_via_kruncher():
        # Enqueue on the manual queue; the fleet runs it (ahead of periodic work).
        job = jobs_store.create_adhoc_job(
            target_type=target_type, target=target, mode=mode.value,
            families=fam_values, scanners=scanners, surface="mcp",
            upload_id=upload_id,
        )
        final = await _await_job(job["id"], timeout=_scan_timeout())
        if final is None:
            return f"Scan job #{job['id']} disappeared from the queue."
        status = final["status"]
        if status == "done":
            return _format_report_from_disk(final, with_graph_report=with_graph_report)
        if status in ("queued", "running"):
            return (
                f"Scan job #{final['id']} is still {status} after "
                f"{_scan_timeout()}s - the kruncher fleet may be busy or "
                f"unavailable. It will keep running; check the dashboard."
            )
        return f"Scan failed (job #{final['id']}): {final.get('error') or status}"

    # Inline (local stdio, or forced off): run it in-process and return the report.
    job = jobs_store.create_adhoc_job(
        target_type=target_type, target=target, mode=mode.value,
        families=fam_values, scanners=scanners, surface="mcp",
        upload_id=upload_id, start_running=True,
    )
    try:
        report = await jobs_worker.run_job_inline(job, allow_local_paths=True)
    except Exception as exc:  # noqa: BLE001 - already recorded as a failed job
        return f"Scan failed (job #{job['id']}): {exc}"

    report_dir = jobs_config.data_dir() / "reports" / f"job-{job['id']}"
    summary = report.to_dict()["summary"]
    header = (
        f"Report written to {report_dir} (json/md/html/sarif/junit/pdf). Job #{job['id']}. "
        f"Summary: {json.dumps(summary)}\n\n"
    )
    prov = report.provenance or {}
    header += _source_line(prov.get("source_path"), prov.get("upload_id"))
    body = render(report, "md")
    if report.triage:
        header += "Triage report (json/md/html) also written.\n\n"
        body += "\n\n## " + render_triage_console(report.triage).strip()
    out = header + body
    # Family / full scans also surface the final report's code-graph report; a
    # single scanner (scan_with) returns only its own report.
    if with_graph_report:
        graph = _read_graph_report(report_dir)
        out += "\n\n" + (graph or (
            "## Graph report\n\n"
            "_No code graph available - the `analysis` scanner did not run for "
            "this scan._"
        ))
    return out


@mcp.tool()
async def static_scan(project_dir: str | None = None, upload_id: str | None = None) -> str:
    """Run all static scanners (SAST, SCA, secrets, IaC, license, pipeline) over
    a project, deduplicate, and return a Markdown report plus the graph report.

    stdio: pass ``project_dir`` (a local path). http: upload first and pass
    ``upload_id`` (or set DEEPSCAN_MCP_ALLOW_LOCAL_PATHS to use ``project_dir``)."""
    try:
        return await _run_job(
            mode=Mode.STATIC, project_dir=project_dir, upload_id=upload_id
        )
    except (ScanTargetError, ValueError) as exc:
        return f"Error: {exc}"


@mcp.tool()
async def dynamic_scan(target_url: str) -> str:
    """Run all dynamic (DAST) scanners against a running http(s) target URL,
    deduplicate, and return a Markdown report."""
    try:
        return await _run_job(mode=Mode.DYNAMIC, target_url=target_url)
    except (ScanTargetError, ValueError) as exc:
        return f"Error: {exc}"


@mcp.tool()
async def scan_family(
    family: str,
    project_dir: str | None = None,
    upload_id: str | None = None,
    target_url: str | None = None,
) -> str:
    """Run only the scanners of one family, returning the report plus graph report.

    family: one of sast, sca, secret, iac, license, pipeline, dast, analysis, ai.
        The ``analysis`` family is the code-graph taint/sanitization scanner;
        ``ai`` runs the LLM triage over the other scanners' findings (needs the
        claude CLI + a model; producers are run automatically).
    Static families: pass ``project_dir`` (stdio) or ``upload_id`` (http). The
    ``dast`` family: pass ``target_url``.
    """
    try:
        fams = _families([family])
        mode = Mode.DYNAMIC if family.strip().lower() == "dast" else Mode.STATIC
        return await _run_job(
            mode=mode,
            project_dir=project_dir,
            upload_id=upload_id,
            target_url=target_url,
            families=fams,
        )
    except (ScanTargetError, ValueError) as exc:
        return f"Error: {exc}"


@mcp.tool()
async def scan_with(
    scanner: str,
    project_dir: str | None = None,
    upload_id: str | None = None,
    target_url: str | None = None,
) -> str:
    """Run a single named scanner and return that scanner's report. Use
    list_scanners to see available names. Static scanners: pass ``project_dir``
    (stdio) or ``upload_id`` (http); dynamic scanners: pass ``target_url``."""
    try:
        scanner_obj = registry.get(scanner)
        return await _run_job(
            mode=scanner_obj.mode,
            project_dir=project_dir,
            upload_id=upload_id,
            target_url=target_url,
            scanners=[scanner],
            with_graph_report=False,
        )
    except (ScanTargetError, ValueError) as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_graph_questions() -> list[dict[str, str]]:
    """List the precise AppSec questions the analysis code graph can answer.
    Pass a returned ``question`` key to ``query_graph``."""
    return [{"question": k, "label": v} for k, v in QUESTIONS.items()]


@mcp.tool()
def query_graph(
    project_dir: str,
    question: str,
    target: str | None = None,
    limit: int = 40,
    refresh: bool = False,
) -> dict[str, Any]:
    """Query a project's analysis code graph for a precise security question.

    ``question``: one of ``list_graph_questions()`` (e.g. ``unsanitized_sources``,
    ``critical_functions``, ``endpoints_reach_sink``, ``attack_paths``,
    ``blast_radius``). ``target``: the component (function/file name or path) for
    ``blast_radius``. ``limit``: max items/paths returned. The first call builds
    the graph (deterministic, no network); subsequent calls are cached unless
    ``refresh=True``. Returns resolved nodes/paths with ``label`` + ``location``.
    """
    if question not in QUESTIONS:
        return {"error": f"Unknown question {question!r}. Available: {', '.join(QUESTIONS)}"}
    try:
        payload = _graph_payload(project_dir, refresh)
    except ScanTargetError as exc:
        return {"error": f"Invalid project_dir: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"graph build failed: {exc}"}
    if payload is None:
        return {"error": "Could not build the code graph for this project (no code, or graphoofy unavailable)."}
    return answer(payload, question, target=target, limit=limit)


@mcp.tool()
def list_scanners() -> list[dict[str, str]]:
    """List every available scanner with its family, mode and the backing tool."""
    return registry.describe()


@mcp.tool()
def tool_status() -> list[dict[str, Any]]:
    """Report which scanner binaries / docker images are installed."""
    return [
        {
            "name": s.name,
            "version": s.version,
            "kind": s.kind,
            "installed": s.installed,
            "path": s.path,
        }
        for s in install.status_all()
    ]


@mcp.tool()
def install_tool(name: str) -> dict[str, Any]:
    """Securely install one scanner tool (pinned version, checksum-verified).
    Use 'all' to install every tool."""
    try:
        if name.strip().lower() == "all":
            results = install.install_all()
            return {"installed": [s.name for s in results if s.installed]}
        status = install.install(name)
        return {"name": status.name, "installed": status.installed, "path": status.path}
    except install.InstallError as exc:
        return {"error": str(exc)}


@mcp.custom_route("/upload", methods=["POST"])
async def upload(request):  # pragma: no cover - exercised over http only
    """Receive a project zip (raw body, Content-Type application/zip), extract it
    into the shared uploads area and return an ``upload_id`` to pass to a scan
    tool. Only reachable over the streamable-http transport."""
    from starlette.responses import JSONResponse

    filename = request.query_params.get("filename")
    fd, tmp_name = tempfile.mkstemp(suffix=".zip", prefix="deepscan-mcp-upload-")
    try:
        size = 0
        with os.fdopen(fd, "wb") as tmp:
            async for chunk in request.stream():
                size += len(chunk)
                if size > _MAX_UPLOAD_BYTES:
                    return JSONResponse({"error": "Upload exceeds the 200 MiB limit."}, status_code=413)
                tmp.write(chunk)
        if size == 0:
            return JSONResponse({"error": "Uploaded file is empty."}, status_code=400)
        try:
            row = await asyncio.to_thread(jobs_uploads.stage_zip, tmp_name, filename)
        except TargetError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
    return JSONResponse({"upload_id": row["id"], "filename": row["filename"]})


def main() -> None:
    global _TRANSPORT
    parser = argparse.ArgumentParser(description="Deep Scan MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default=os.environ.get("DEEPSCAN_MCP_TRANSPORT", "stdio"),
        help="MCP transport (default: stdio; streamable-http serves on :8000/mcp).",
    )
    args = parser.parse_args()
    _TRANSPORT = args.transport
    from deepscan_core.log import get_logger, setup_logging
    from deepscan_jobs import config as jobs_config
    from deepscan_jobs import db as jobs_db

    setup_logging()
    log = get_logger("mcp")
    # The streamable-http bind address. FastMCP ignores FASTMCP_HOST/PORT from the
    # environment (its __init__ passes the 127.0.0.1 default explicitly into its
    # pydantic Settings, which overrides the env var), so apply them here - needed
    # to bind 0.0.0.0 inside a container. Defaults stay 127.0.0.1:8000.
    host = os.environ.get("FASTMCP_HOST") or os.environ.get("DEEPSCAN_MCP_HOST")
    port = os.environ.get("FASTMCP_PORT") or os.environ.get("DEEPSCAN_MCP_PORT")
    if host:
        mcp.settings.host = host
    if port:
        try:
            mcp.settings.port = int(port)
        except ValueError:
            log.warning("ignoring non-integer port %r", port)
    # DNS-rebinding protection. FastMCP auto-enables it at construction time, but
    # because `mcp` is built with the default host (127.0.0.1), the Host allow-list
    # is locked to localhost. Binding to 0.0.0.0 above would then reject every
    # non-loopback request (e.g. a LAN client hitting http://<lan-ip>:8000/mcp)
    # with 421 Misdirected Request. Rebuild the allow-list here so external Host
    # values are accepted: localhost always, plus the bind host and any operator-
    # provided extras (DEEPSCAN_MCP_ALLOWED_HOSTS / _ALLOWED_ORIGINS, comma-
    # separated; entries may use the "host:*" any-port wildcard). Set
    # DEEPSCAN_MCP_DISABLE_DNS_REBINDING=1 to turn the protection off entirely.
    if args.transport != "stdio":
        from mcp.server.transport_security import TransportSecuritySettings

        def _csv(name: str) -> list[str]:
            return [v.strip() for v in (_config_get(name) or "").split(",") if v.strip()]

        if (_config_get("DEEPSCAN_MCP_DISABLE_DNS_REBINDING") or "").strip().lower() in (
            "1", "true", "yes", "on",
        ):
            log.warning("DNS-rebinding protection disabled (DEEPSCAN_MCP_DISABLE_DNS_REBINDING)")
            mcp.settings.transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=False,
            )
        else:
            bind_host = mcp.settings.host
            hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
            origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
            # When bound to a concrete address (not the 0.0.0.0/:: wildcard), allow
            # that address too. For a wildcard bind, the operator must name the
            # reachable hostnames/IPs via DEEPSCAN_MCP_ALLOWED_HOSTS.
            if bind_host not in ("0.0.0.0", "::", ""):
                hosts.append(f"{bind_host}:*")
                origins.append(f"http://{bind_host}:*")
            hosts += _csv("DEEPSCAN_MCP_ALLOWED_HOSTS")
            origins += _csv("DEEPSCAN_MCP_ALLOWED_ORIGINS")
            mcp.settings.transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=hosts,
                allowed_origins=origins,
            )
    # Scans become jobs in the shared Postgres store; ensure the (idempotent)
    # schema exists before serving. A clear error beats opaque tool failures.
    try:
        jobs_db.init_schema()
    except Exception as exc:  # noqa: BLE001
        log.error(
            "cannot reach the job store at %s - set DEEPSCAN_DB_DSN or "
            "DEEPSCAN_DB_HOST/PORT/NAME/USER/PASSWORD. (%s)",
            jobs_config.database_dsn().split("@")[-1], exc,
        )
        raise SystemExit(1) from exc
    try:
        mcp.run(args.transport)
    except KeyboardInterrupt:
        # SIGINT / CTRL+C is a normal way to stop the server. anyio re-raises the
        # KeyboardInterrupt (chained with the event loop's CancelledError) out of
        # ``mcp.run``; swallow it so we exit cleanly with no traceback.
        log.info("interrupted - shutting down")
    finally:
        # Close the Postgres pool now so its finalizer doesn't try to log during
        # interpreter shutdown (which raises a noisy ImportError traceback).
        jobs_db.close_pool()


if __name__ == "__main__":
    main()
