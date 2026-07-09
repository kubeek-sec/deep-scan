"""The HTML reports (findings + triage) carry the shared dark/branded theme."""

from __future__ import annotations

from deepscan_core.models import (
    DedupedFinding,
    Family,
    Mode,
    Report,
    Severity,
    ToolResult,
    ToolStatus,
)
from deepscan_core.reporting import render_html
from deepscan_core.reporting.render_triage import render_triage_html


def _report() -> Report:
    return Report(
        mode=Mode.STATIC, target="/p/demo", generated_at="t", duration=1.0,
        tools=[ToolResult(scanner="analysis", family=Family.ANALYSIS,
                          status=ToolStatus.OK, duration=0.1, findings=[])],
        findings=[DedupedFinding(severity=Severity.CRITICAL, location="app.py:10",
                                 message="command-injection", tools=["analysis"],
                                 rules=["CWE-78"], families=["analysis"], cwes=["CWE-78"],
                                 occurrences=1, fingerprints=["a"])],
    )


def _assert_branded_dark(html: str) -> None:
    assert "<!doctype html>" in html
    assert "◈" in html and "Deep&nbsp;Scan" in html        # brand mark + wordmark
    assert "--bg:#0d1117" in html                           # web dark background
    assert "--accent:#3fb6a8" in html                       # teal accent


def test_findings_html_is_branded_dark():
    html = render_html(_report())
    _assert_branded_dark(html)
    assert "app.py:10" in html and 'class="chip critical"' in html


def test_triage_html_is_branded_dark():
    triage = {"summary": "s", "items": [{"title": "RCE", "location": "app.py:10",
              "severity": "critical", "priority": "P0", "real_risk": "r",
              "exploitability": "trivial", "confidence": "high", "rationale": "x",
              "recommendation": "y"}], "recommendations": [], "deprioritized": [],
              "meta": {"engine": "claude-cli", "model": "m"}}
    html = render_triage_html(triage, _report())
    _assert_branded_dark(html)
    assert "P0" in html and 'class="chip critical"' in html
