"""Tests for the graph security features: choke points (#1) and
reachable-dependency correlation (#2)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from deepscan_core.analysis import analyze_target, dep_usage
from deepscan_core.models import Family, Finding, Severity
from deepscan_core.scanners import ScanContext
from deepscan_core.scanners.reachable_deps import ReachableDeps


# ----------------------------- #1 choke points ----------------------------- #

def test_choke_points_cover_multiple_findings_at_a_shared_function(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os, sqlite3\n"
        "db = sqlite3.connect(':memory:').cursor()\n"
        "def run_cmd(v):\n"
        "    os.system('echo ' + v)\n"
        "def query(v):\n"
        "    db.execute('SELECT * FROM t WHERE x=' + v)\n"
        "def process(v):\n"
        "    run_cmd(v)\n"
        "    query(v)\n"
        "def handle_request(request):\n"
        "    process(request.args.get('v'))\n",
        encoding="utf-8",
    )
    res = analyze_target(tmp_path, tmp_path / "_w", None)
    chokes = {c["label"]: c for c in res.graph_summary.get("choke_points", [])}
    # process() lies on every path to both sinks → covers 2 findings
    assert "process()" in chokes and chokes["process()"]["covers"] == 2
    # each finding is annotated with where to fix
    for f in res.findings:
        if f.extra.get("kind") in ("command-injection", "sql-injection"):
            labels = [c["label"] for c in f.extra.get("choke_points", [])]
            assert "process()" in labels


def test_security_graph_payload_tags_and_layers(tmp_path):
    import json
    import re

    (tmp_path / "app.py").write_text(
        "import os, sqlite3\n"
        "db = sqlite3.connect(':memory:').cursor()\n"
        "def run_cmd(v):\n    os.system('echo ' + v)\n"
        "def query(v):\n    db.execute('SELECT * FROM t WHERE x=' + v)\n"
        "def process(v):\n    run_cmd(v)\n    query(v)\n"
        "def handle_request(request):\n    process(request.args.get('v'))\n",
        encoding="utf-8",
    )
    raw = tmp_path / "raw"
    res = analyze_target(tmp_path, tmp_path / "_w", raw)
    sg = res.graph_summary["security_graph"]
    assert sg["sinks"] >= 2 and sg["endpoints"] >= 1 and sg["critical"] >= 1
    data = json.loads(re.search(r"const DATA = (\{.*?\});", (raw / "graph.html").read_text(), re.S).group(1))
    tagged = {n["label"]: n["tags"] for n in data["nodes"] if n["tags"]}
    assert any("SINK" in t for t in tagged.values())
    assert any("ENTRY" in t for t in tagged.values())
    assert any("CRITICAL" in t for t in tagged.values())
    # nodes carry precomputed positions (fast load) and metrics
    assert all("x" in n and "y" in n for n in data["nodes"])
    # attack-path layer found an entry → sink path
    assert data["layers"]["attack_paths"]["paths"]


def test_graph_query_answers_security_questions(tmp_path):
    from deepscan_core.analysis import QUESTIONS, answer, security_payload

    (tmp_path / "app.py").write_text(
        "import os, sqlite3\n"
        "db = sqlite3.connect(':memory:').cursor()\n"
        "def run_cmd(v):\n    os.system('echo ' + v)\n"
        "def query(v):\n    db.execute('SELECT * FROM t WHERE x=' + v)\n"
        "def process(v):\n    run_cmd(v)\n    query(v)\n"
        "def handle_request(request):\n    process(request.args.get('v'))\n",
        encoding="utf-8",
    )
    payload = security_payload(tmp_path, tmp_path / "_w")
    assert payload is not None

    # every question answers without error
    for q in QUESTIONS:
        a = answer(payload, q, target="run_cmd" if q == "blast_radius" else None, limit=10)
        assert "error" not in a, (q, a)

    crit = answer(payload, "critical_functions", limit=10)
    assert crit["items"] and crit["items"][0]["label"] == "process()"  # highest hotness

    eps = answer(payload, "endpoints_reach_sink", limit=10)
    assert any(i["label"] == "handle_request()" for i in eps["items"])

    atk = answer(payload, "attack_paths", limit=10)
    assert atk["paths"] and atk["paths"][0][0]["label"] == "handle_request()"

    blast = answer(payload, "blast_radius", target="run_cmd", limit=10)
    assert blast["target"]["label"] == "run_cmd()" and blast["impact_count"] >= 1

    assert answer(payload, "nope")["error"]


# ------------------------- #2 reachable dependencies ------------------------ #

def _sca(rule, pkg, sev=Severity.HIGH):
    return Finding(
        tool="trivy", family=Family.SCA, rule=rule, severity=sev,
        message=f"Package: {pkg}  Installed Version: 1.0  Vulnerability {rule}",
        location="requirements.txt",
    )


def _project(tmp_path):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "def handler(request):\n"
        "    return requests.get(request.args.get('u'))\n",
        encoding="utf-8",
    )
    return tmp_path


def test_reachable_dep_used_vs_unused(tmp_path):
    _project(tmp_path)
    findings = dep_usage.analyze(
        tmp_path, tmp_path / "_w",
        [_sca("CVE-1", "requests"), _sca("CVE-2", "leftpad", Severity.CRITICAL)],
    )
    by_rule = {f.rule: f for f in findings}
    assert by_rule["CVE-1"].extra["verdict"] in ("used-reachable", "used-unreachable")
    assert by_rule["CVE-1"].extra["matched_imports"] == ["requests"]
    # unused dependency is downgraded and flagged not-found
    assert by_rule["CVE-2"].extra["verdict"] == "not-found"
    assert by_rule["CVE-2"].severity is not Severity.CRITICAL


def test_reachable_deps_scanner_skips_without_sca(tmp_path):
    _project(tmp_path)
    ctx = ScanContext(work_dir=tmp_path / "_w", target_path=tmp_path, prior_findings=[])
    result = asyncio.run(ReachableDeps().run(ctx))
    assert result.status.value == "skipped"


def test_reachable_deps_scanner_emits_correlation(tmp_path):
    _project(tmp_path)
    ctx = ScanContext(
        work_dir=tmp_path / "_w", target_path=tmp_path,
        prior_findings=[_sca("CVE-1", "requests")],
    )
    result = asyncio.run(ReachableDeps().run(ctx))
    assert result.status.value == "ok"
    assert result.findings and result.findings[0].tool == "reachable-deps"
    assert result.findings[0].extra["matched_imports"] == ["requests"]
