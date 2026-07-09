"""Tests for the `analysis` code-graph security scanner."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from deepscan_core.analysis import analyze_target
from deepscan_core.analysis import taint, ts_taint
from deepscan_core.models import Family, Severity
from deepscan_core.scanners import ScanContext
from deepscan_core.scanners.analysis import Analysis

GUINEA_PY = Path("guinea-pig/src/python")
GUINEA_SRC = Path("guinea-pig/src")

# (language dir, glob, expected sink kind, vulnerable-file stem). Each fixture is
# a cross-function flow (param → helper → sink) with a *_patched sibling that
# must produce no taint finding.
_TS_TAINT_CASES = [
    ("javascript", "*.js", "command-injection", "command_injection.js"),
    ("typescript", "*.ts", "sql-injection", "sql_injection.ts"),
    ("java", "*.java", "sql-injection", "SqlInjection.java"),
    ("go", "*.go", "sql-injection", "sql_injection.go"),
    ("ruby", "*.rb", "command-injection", "command_injection.rb"),
    ("php", "*.php", "command-injection", "command_injection.php"),
    ("csharp", "*.cs", "sql-injection", "SqlInjection.cs"),
    ("rust", "*.rs", "command-injection", "command_injection.rs"),
    ("c", "*.c", "command-injection", "command_injection.c"),
]


def test_python_taint_finds_known_sinks_and_skips_patched():
    files = sorted(GUINEA_PY.rglob("*.py"))
    paths = taint.find_taint_paths(taint.build_graph(files, GUINEA_PY))
    sinks_found = {(p.kind, p.file.split("/")[-1]) for p in paths}
    assert ("command-injection", "command_injection.py") in sinks_found
    assert ("sql-injection", "sql_injection.py") in sinks_found
    assert ("deserialization", "deserialization.py") in sinks_found
    # The sanitizer-aware engine must NOT flag the *_patched siblings.
    assert not any("patched" in p.file for p in paths)


@pytest.mark.parametrize("lang,glob,kind,stem", _TS_TAINT_CASES)
def test_ts_taint_finds_known_and_skips_patched(lang, glob, kind, stem):
    """The tree-sitter taint engine proves the cross-function flow in each
    language's vulnerable fixture and leaves its *_patched sibling clean."""
    d = GUINEA_SRC / lang
    if not d.is_dir():
        pytest.skip(f"no {lang} fixtures")
    if ts_taint._load_parser(next(d.rglob(glob)).suffix.lower()) is None:
        pytest.skip(f"tree-sitter grammar for {lang} not available")
    paths = ts_taint.find_taint_paths(ts_taint.build_graph(sorted(d.rglob(glob)), d))
    found = {(p.kind, p.file.split("/")[-1]) for p in paths}
    assert (kind, stem) in found, f"{lang}: expected {kind} in {stem}, got {sorted(found)}"
    # the sanitizer/safe-form-aware engine must NOT flag the *_patched siblings.
    assert not any("patched" in p.file.lower() for p in paths)


def test_ts_taint_findings_carry_engine_and_chain(tmp_path):
    """A non-Python taint finding carries a per-family engine label and a chain."""
    res = analyze_target(GUINEA_SRC / "go", tmp_path / "_work", None)
    ts = [
        f for f in res.findings
        if str(f.extra.get("engine", "")).startswith("analysis/taint-")
        and f.extra.get("engine") != "analysis/taint-python"
    ]
    assert ts, "expected tree-sitter taint findings on the Go fixtures"
    assert all(f.extra.get("taint_chain") for f in ts)
    assert all(f.extra.get("engine") == "analysis/taint-go" for f in ts)


def test_graph_html_embeds_payload_and_ui():
    import json
    import re

    from deepscan_core.analysis.graph_html import render_graph_html

    payload = {
        "nodes": [{"id": "a", "label": "handle()", "type": "function", "file": "f.py",
                   "line": "2", "community": 0, "degree": 2, "fan_in": 0, "fan_out": 1,
                   "tags": ["ENTRY"], "metrics": {"hotness": 5, "reachable_sinks": 1,
                                                   "pagerank": 0.1, "betweenness": 0.0},
                   "x": 1.0, "y": 2.0}],
        "edges": [{"from": "a", "to": "a", "rel": "CALLS"}],
        "layers": {k: {"nodes": [], "note": ""} for k in
                   ("unsanitized", "critical", "ep_reach_sink", "ep_reach_taint",
                    "shortest_critical", "all_paths_critical", "external_deps",
                    "deps_to_critical", "attack_paths", "blast_radius")},
        "counts": {"functions": 1, "endpoints": 1, "sinks": 0, "critical": 0, "external": 0},
        "communityCount": 1,
    }
    html = render_graph_html(payload)
    # UI markers: layer selector, the requested interactions, the layers
    for marker in ('id="layer"', "Ctrl+drag", "function reorg", "blast_radius",
                   "dragStart", "moveNode", "DATA.layers", "buildFilters"):
        assert marker in html
    data = json.loads(re.search(r"const DATA = (\{.*?\});", html, re.S).group(1))
    assert data["nodes"][0]["tags"] == ["ENTRY"] and "attack_paths" in data["layers"]


def test_analysis_scanner_emits_findings_and_graph_artifacts():
    import asyncio

    async def run():
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as raw:
            ctx = ScanContext(work_dir=Path(tmp), raw_dir=Path(raw), target_path=GUINEA_SRC)
            result = await Analysis().run(ctx)
            artifacts = {p.name for p in Path(raw).glob("*")}
            return result, artifacts

    result, artifacts = asyncio.run(run())
    assert result.status.value == "ok"
    assert result.findings, "expected findings on the vulnerable corpus"
    assert all(f.family is Family.ANALYSIS for f in result.findings)
    # high-confidence Python taint findings carry a CWE and a taint chain
    py = [f for f in result.findings if f.extra.get("engine") == "analysis/taint-python"]
    assert py and all(f.extra.get("taint_chain") for f in py)
    assert "analysis.json" in artifacts
    assert "graph.json" in artifacts


def test_analyze_target_returns_graph_summary():
    with tempfile.TemporaryDirectory() as tmp:
        res = analyze_target(GUINEA_PY, Path(tmp), None)
    assert res.graph_summary.get("nodes", 0) > 0
    assert res.graph_summary.get("entry_points", 0) > 0
    assert isinstance(res.findings, list) and res.findings
    # severity must come from the knowledge base, not a default
    assert any(f.severity is Severity.CRITICAL for f in res.findings)
    # every finding carries the reachability shape
    assert all("reachable_from_entrypoint" in f.extra for f in res.findings)


def test_reachability_traces_multi_hop_path_to_entry_point(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def run_cmd(cmd):\n"
        "    os.system(cmd)\n"
        "def build_and_run(name):\n"
        "    run_cmd('echo ' + name)\n"
        "def handle_request(request):\n"
        "    name = request.args.get('name')\n"
        "    build_and_run(name)\n",
        encoding="utf-8",
    )
    res = analyze_target(tmp_path, tmp_path / "_work", None)
    # the sink lives in run_cmd, reachable from the web handler two hops up
    sink = next(f for f in res.findings if f.extra.get("kind") == "command-injection")
    assert sink.extra["reachable_from_entrypoint"] is True
    assert sink.extra["entry_kind"] == "web"
    assert sink.extra["call_distance"] == 2
    assert sink.extra["call_path"][0] == "handle_request()"
    assert sink.extra["call_path"][-1] == "run_cmd()"
    # exactly one entry point (handle_request has no in-repo caller)
    assert res.graph_summary["entry_points"] == 1
