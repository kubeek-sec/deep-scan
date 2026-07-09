"""Orchestrate the code-graph security analysis.

1. Build the graphoofy code graph (knowledge base + structural summary) and,
   when an artifact dir is given, write ``graph.json`` / ``graph.html``.
2. Run the precise Python AST taint engine and the multi-language tree-sitter
   sink scan.
3. Compute call-graph **reachability** (is the enclosing function reachable from
   an entry point, and by what path) and use it to enrich every finding and to
   adjust the severity/confidence of the structural "risk zone" findings.

Nothing here executes target code (AST / tree-sitter parsing only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config
from ..log import get_logger
from ..models import Family, Finding
from . import chokepoints, sinks, suppress, taint, ts_taint
from .reachability import CallGraph, ReachInfo

_log = get_logger("analysis")


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    graph_summary: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)  # name -> path


# graphoofy ``file_type`` values that are documentation/prose, not code. The
# security graph keeps only ``code`` (and ``concept`` - external/stdlib call
# targets, which are code structure).
_NON_CODE_FILE_TYPES = frozenset({"document", "rationale", "paper", "image"})


def _keep_code_only(G) -> None:
    """Drop documentation/comment nodes (and their edges) from the graph."""
    drop = [n for n, d in G.nodes(data=True) if d.get("file_type") in _NON_CODE_FILE_TYPES]
    G.remove_nodes_from(drop)


def _build_graph(files: list[Path], work_dir: Path, artifacts_dir: Path | None):
    """Build the graphoofy graph. Returns (summary, artifacts, call_graph).
    Best-effort: any failure yields an empty summary and ``None`` call graph so
    the security analysis still runs (without reachability)."""
    summary: dict[str, Any] = {}
    artifacts: dict[str, str] = {}
    try:
        from graphoofy.analyze import god_nodes
        from graphoofy.build import build_from_json
        from graphoofy.cluster import cluster
        from graphoofy.extract import extract
    except Exception as exc:  # graphoofy or a dep missing
        summary["error"] = f"graph unavailable: {exc}"
        return summary, artifacts, None, None, {}

    try:
        # Parse files across cores (ProcessPoolExecutor) so a large repo's graph
        # doesn't take tens of minutes; ``DEEPSCAN_GRAPH_WORKERS`` bounds/disables
        # it on shared hosts. We already run off the event loop (a worker thread),
        # and the kruncher worker handles one job at a time, so only one pool is
        # ever live per worker process.
        workers = config.graph_extract_workers()
        extraction = extract(
            files,
            cache_root=work_dir,
            parallel=workers != 0,
            max_workers=workers or None,
            start_method=config.graph_extract_start_method(),
        )
        G = build_from_json(extraction, directed=True)
    except Exception as exc:  # noqa: BLE001
        summary["error"] = f"graph build failed: {exc}"
        return summary, artifacts, None, None, {}

    # graphoofy is a general knowledge-graph tool: it also models prose - markdown
    # files become ``document`` nodes and Python docstrings / rationale comments
    # (``# NOTE:`` …) become ``rationale`` nodes, plus ``paper``/``image`` nodes
    # for ingested docs. A *security* code graph wants code structure only, so
    # drop those node types (and their edges) before clustering/export/view.
    _keep_code_only(G)

    try:
        communities = cluster(G) or {}
    except Exception:  # noqa: BLE001
        communities = {}
    try:
        hubs = god_nodes(G, top_n=10)
    except Exception:  # noqa: BLE001
        hubs = []

    try:
        call_graph = CallGraph(extraction)
    except Exception:  # noqa: BLE001
        call_graph = None

    summary = {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "communities": len(communities),
        "functions": call_graph.function_count if call_graph else 0,
        "entry_points": call_graph.entry_point_count if call_graph else 0,
        "god_nodes": [
            {"label": h.get("label"), "degree": h.get("degree")} for h in hubs
        ],
    }

    if artifacts_dir is not None:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        try:
            from graphoofy.export import to_json

            out = artifacts_dir / "graph.json"
            to_json(G, communities, str(out), force=True)
            if out.exists():
                artifacts["graph.json"] = str(out)
        except Exception:  # noqa: BLE001
            pass
    return summary, artifacts, call_graph, G, communities


def _reach_fields(info: ReachInfo | None) -> dict[str, Any]:
    """Reachability fields attached to a finding's ``extra`` (always present so
    the shape is stable, even when reachability could not be computed)."""
    if info is None:
        return {"reachable_from_entrypoint": None, "entry_point": None,
                "entry_kind": "unknown", "call_distance": None, "call_path": []}
    return {
        "reachable_from_entrypoint": info.reachable,
        "entry_point": info.entry_point,
        "entry_kind": info.entry_kind,
        "call_distance": info.distance if info.distance >= 0 else None,
        "call_path": info.call_path,
    }


def _finding_from_path(p, cg: CallGraph | None) -> Finding:
    """Build a Finding from a proven taint path (Python or tree-sitter engine).

    The ``engine`` label is per language family (``analysis/taint-python``,
    ``analysis/taint-go`` …) so downstream consumers can tell which collector
    produced it; everything else is identical across languages.
    """
    info = cg.lookup(p.file, p.line) if cg else None
    # Base confidence comes from the taint engine (explicit source vs assumed
    # parameter); a confirmed path from a web/CLI entry point is real exposure,
    # so it raises a "medium" to "high".
    confidence = p.confidence
    if info and info.reachable and info.entry_kind in ("web", "cli"):
        confidence = "high"
    extra = {
        "engine": f"analysis/taint-{p.family}",
        "kind": p.kind,
        "confidence": confidence,
        "reachable": True,  # taint proved a data-flow to the sink
        "sanitized": False,
        "taint_chain": p.chain,
        "features": p.features,
        "remediation": sinks.remediation(p.kind),
    }
    extra.update(_reach_fields(info))
    return Finding(
        tool="analysis",
        family=Family.ANALYSIS,
        rule=p.cwe or p.kind,
        severity=sinks.spec(p.kind).severity,
        message=_taint_message(p, info),
        location=f"{p.file}:{p.line}",
        cwes=[p.cwe] if p.cwe.upper().startswith("CWE-") else [],
        extra=extra,
    )


def _taint_findings(
    files: list[Path], root: Path, cg: CallGraph | None, *, deadline=None, should_stop=None
) -> list[Finding]:
    """Precise Python AST taint engine."""
    return [
        _finding_from_path(p, cg)
        for p in taint.analyze_python(files, root, deadline=deadline, should_stop=should_stop)
    ]


def _ts_taint_findings(
    files: list[Path], root: Path, cg: CallGraph | None, *, deadline=None, should_stop=None
) -> list[Finding]:
    """Precise tree-sitter taint engine for every non-Python supported family."""
    return [
        _finding_from_path(p, cg)
        for p in ts_taint.analyze_ts(files, root, deadline=deadline, should_stop=should_stop)
    ]


def _apply_nosec(findings: list[Finding], files: list[Path], root: Path):
    """Drop findings whose sink line carries a covering ``# nosec``. Returns
    ``(kept, suppressed_count)``."""
    nmap = suppress.collect(files, root)
    if not nmap:
        return findings, 0
    kept: list[Finding] = []
    suppressed = 0
    for f in findings:
        file, _, line_s = f.location.partition(":")
        try:
            line = int(line_s)
        except ValueError:
            kept.append(f)
            continue
        kind = str(f.extra.get("kind", ""))
        cwe = f.cwes[0] if f.cwes else ""
        if suppress.is_suppressed(nmap, file, line, kind, cwe):
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed


def _taint_message(p, info: ReachInfo | None) -> str:
    base = (
        f"{p.kind}: untrusted input reaches {p.sink}() without sanitization "
        f"(cross-function taint path)"
    )
    if info and info.reachable and info.entry_kind in ("web", "cli"):
        return base + f" - reachable from {info.entry_kind} entry point {info.entry_point}"
    return base


def analyze_target(
    target: Path,
    work_dir: Path,
    artifacts_dir: Path | None = None,
    *,
    deadline: float | None = None,
    should_stop=None,
) -> AnalysisResult:
    """Analyze a directory (or single file): build the graph and find risk zones.

    ``deadline`` (a ``time.monotonic()`` value) and ``should_stop`` (a callback)
    bound the CPU-bound taint pass; either tripping raises
    :class:`~deepscan_core.analysis.taint_core.AnalysisAborted`."""
    findings, summary, artifacts, cg, G, communities = _analyze(
        target, work_dir, artifacts_dir, deadline=deadline, should_stop=should_stop
    )

    # Security-annotated interactive graph view + queryable payload.
    if artifacts_dir is not None and G is not None:
        try:
            from . import graph_view
            from .graph_html import render_graph_html

            payload = graph_view.build(G, findings, cg, communities)
            (artifacts_dir / "graph.html").write_text(render_graph_html(payload), encoding="utf-8")
            artifacts["graph.html"] = str(artifacts_dir / "graph.html")
            # Machine-readable payload so the graph can be queried after the scan.
            import json as _json

            (artifacts_dir / "graph.view.json").write_text(_json.dumps(payload), encoding="utf-8")
            artifacts["graph.view.json"] = str(artifacts_dir / "graph.view.json")
            summary["security_graph"] = payload["counts"]
            _log.debug("graph.html: %s", payload["counts"])
        except Exception as exc:  # noqa: BLE001
            _log.debug("graph.html render skipped: %s", exc)

    return AnalysisResult(findings=findings, graph_summary=summary, artifacts=artifacts)


def _analyze(target: Path, work_dir: Path, artifacts_dir: Path | None, *, deadline=None, should_stop=None):
    """Shared core: collect files, build the graph + findings + choke points.
    Returns (findings, summary, artifacts, cg, G, communities)."""
    try:
        from graphoofy.extract import collect_files

        files = collect_files(target)
    except Exception:  # noqa: BLE001 - fall back to a plain code-file walk
        files = _walk_code_files(target)

    root = target if target.is_dir() else target.parent
    _log.debug("collected %d code file(s) under %s", len(files), target)
    summary, artifacts, cg, G, communities = _build_graph(files, work_dir, artifacts_dir)
    _log.debug(
        "graph: %s nodes, %s edges, %s functions, %s entry points",
        summary.get("nodes"), summary.get("edges"),
        summary.get("functions"), summary.get("entry_points"),
    )
    # Two precise engines, routed by extension: the Python AST engine for .py,
    # the tree-sitter engine for every other supported family. File sets are
    # disjoint; a defensive python-wins dedupe by location guards any overlap.
    py_f = _taint_findings(files, root, cg, deadline=deadline, should_stop=should_stop)
    ts_f = _ts_taint_findings(files, root, cg, deadline=deadline, should_stop=should_stop)
    py_locs = {f.location for f in py_f}
    ts_f = [f for f in ts_f if f.location not in py_locs]
    _log.debug("findings: %d python-taint, %d ts-taint", len(py_f), len(ts_f))
    findings = py_f + ts_f
    # Honour inline ``# nosec`` annotations on a sink line (scoped by kind/CWE).
    findings, suppressed = _apply_nosec(findings, files, root)
    if suppressed:
        summary["suppressed_by_nosec"] = suppressed
        _log.debug("suppressed %d finding(s) via # nosec", suppressed)
    if cg is not None and findings:
        try:
            choke = chokepoints.analyze(cg, findings)  # also writes extra["choke_points"]
            summary["choke_points"] = choke["choke_points"]
            _log.debug("choke points: %d", len(choke["choke_points"]))
        except Exception as exc:  # noqa: BLE001 - never fail the scan on analysis extras
            _log.debug("choke-point analysis skipped: %s", exc)
    summary["findings_reachable_from_entry"] = sum(
        1 for f in findings if f.extra.get("reachable_from_entrypoint")
    )
    summary["findings_via_web_or_cli"] = sum(
        1 for f in findings if f.extra.get("entry_kind") in ("web", "cli")
    )
    return findings, summary, artifacts, cg, G, communities


def security_payload(target: Path, work_dir: Path) -> dict | None:
    """Build the security-annotated graph payload for querying (no files written).
    Returns None when the code graph could not be built."""
    from . import graph_view

    findings, _summary, _artifacts, cg, G, communities = _analyze(target, work_dir, None)
    if G is None:
        return None
    return graph_view.build(G, findings, cg, communities)


_CODE_EXTS = set(sinks.EXT_TO_FAMILY) | {".py", ".pyw"}


def _walk_code_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    skip = {".git", ".venv", "node_modules", "__pycache__", ".tox", "dist", "build"}
    out: list[Path] = []
    for p in target.rglob("*"):
        if p.is_file() and p.suffix.lower() in _CODE_EXTS and not (skip & set(p.parts)):
            out.append(p)
    return out
