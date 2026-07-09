"""Tests for anonymous telemetry (metrics.py): the summary payload, the privacy
contract, the disabled-by-default behaviour, and the actual transaction send."""

from __future__ import annotations

import json

import sentry_sdk

from deepscan_core import metrics
from deepscan_core.models import (
    DedupedFinding,
    Family,
    Mode,
    Report,
    Severity,
    ToolResult,
    ToolStatus,
)

_TARGET = "/home/alice/secret-project/src"


def _report() -> Report:
    tools = [
        ToolResult(scanner="analysis", family=Family.ANALYSIS, status=ToolStatus.OK,
                   duration=0.2, findings=[]),
        ToolResult(scanner="codeql", family=Family.SAST, status=ToolStatus.SKIPPED,
                   duration=0.0, skip_reason="not installed"),
    ]
    findings = [
        DedupedFinding(severity=Severity.CRITICAL, location="x.py:1", message="m",
                       tools=["analysis"], rules=["CWE-78"], families=["analysis"],
                       cwes=["CWE-78"], occurrences=1, fingerprints=["a"]),
        DedupedFinding(severity=Severity.HIGH, location="y.py:2", message="m2",
                       tools=["gitleaks"], rules=["secret"], families=["secret"],
                       cwes=[], occurrences=1, fingerprints=["b"]),
    ]
    return Report(mode=Mode.STATIC, target=_TARGET, generated_at="t", duration=1.5,
                  tools=tools, findings=findings)


def test_summary_counts_and_privacy():
    s = metrics.summarize(_report(), "cli")
    assert s["tags"] == {"mode": "static", "surface": "cli", "had_findings": "true"}
    m = s["measurements"]
    assert m["findings.deduped"] == 2
    assert m["scanners.ran"] == 1 and m["scanners.skipped"] == 1
    assert m["severity.critical"] == 1 and m["severity.high"] == 1
    assert m["family.analysis"] == 1 and m["family.secret"] == 1
    # PRIVACY: the target path must not appear anywhere in what we send
    assert _TARGET not in json.dumps(s)


def test_disabled_without_dsn(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.setenv("DEEPSCAN_TELEMETRY", "false")
    metrics._initialized = False
    metrics._enabled = False
    from deepscan_core import config

    config._dotenv_cache = {}  # ignore any .env on disk
    assert metrics.init() is False
    metrics.record_scan(_report(), surface="cli")  # must be a silent no-op


def test_record_emits_anonymous_transaction(monkeypatch):
    captured: list[dict] = []

    def before(event, _hint):
        captured.append(event)
        return None  # capture and drop → no network

    sentry_sdk.init(
        dsn="https://public@example.invalid/1",
        traces_sample_rate=1.0,
        before_send_transaction=before,
    )
    try:
        metrics._record(_report(), "kruncher")
        sentry_sdk.flush(timeout=2)
    finally:
        sentry_sdk.init(dsn="")  # tear down the client

    assert captured, "no transaction captured"
    ev = captured[0]
    assert ev.get("transaction") == "deepscan.scan"
    assert ev["tags"]["surface"] == "kruncher"
    data = ev["contexts"]["trace"]["data"]
    assert data["findings.deduped"] == 2 and data["severity.critical"] == 1
    assert _TARGET not in json.dumps(ev)  # privacy holds end-to-end
