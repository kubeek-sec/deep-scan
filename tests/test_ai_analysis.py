"""Tests for the `ai-analysis` triage scanner and the triage renderers.

The Claude CLI is mocked so these run without a model or network.
"""

from __future__ import annotations

import json
from pathlib import Path

from deepscan_core.ai import claude_cli
from deepscan_core.models import DedupedFinding, Family, Finding, Mode, Report, Severity
from deepscan_core.reporting import render_triage
from deepscan_core.scanners import ScanContext
from deepscan_core.scanners.ai_analysis import AiAnalysis

GUINEA_SRC = Path("guinea-pig/src")

_FAKE_TRIAGE = {
    "summary": "One real RCE risk dominates.",
    "items": [
        {
            "title": "Command injection in ping()",
            "location": "python/command_injection.py:10",
            "severity": "critical",
            "priority": "P0",
            "real_risk": "Arbitrary shell command execution via the host argument.",
            "exploitability": "trivial",
            "confidence": "high",
            "likely_false_positive": False,
            "rationale": "Untrusted host reaches os.system unsanitized.",
            "recommendation": "Use subprocess with an argument list and shell=False.",
            "cwes": ["CWE-78"],
            "related_findings": ["analysis:python/command_injection.py:10"],
        }
    ],
    "recommendations": ["Adopt a central input-validation layer."],
    "deprioritized": [{"location": "x.py:1", "reason": "constant input only"}],
}


def _finding() -> Finding:
    return Finding(
        tool="analysis", family=Family.ANALYSIS, rule="CWE-78",
        severity=Severity.CRITICAL, message="command-injection sink",
        location="python/command_injection.py:10", cwes=["CWE-78"],
        extra={"engine": "analysis/taint-python", "kind": "command-injection"},
    )


def test_ai_analysis_skips_without_claude(monkeypatch):
    import asyncio

    def _raise():
        raise claude_cli.ClaudeUnavailable("not found")

    monkeypatch.setattr(claude_cli, "claude_binary", _raise)
    ctx = ScanContext(work_dir=Path("."), target_path=GUINEA_SRC, prior_findings=[_finding()])
    result = asyncio.run(AiAnalysis().run(ctx))
    assert result.status.value == "skipped"


def test_ai_analysis_produces_triage_payload(monkeypatch, tmp_path):
    import asyncio

    monkeypatch.setattr(claude_cli, "claude_binary", lambda: "claude")

    async def _fake_run(prompt, *, cwd, timeout, add_dirs=None):
        assert "command_injection" in prompt  # findings made it into the prompt
        text = "```json\n" + json.dumps(_FAKE_TRIAGE) + "\n```"
        return claude_cli.ClaudeRun(text=text, raw=text, events=[
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Read", "input": {"file_path": "x.py"}}]}},
            {"type": "result", "is_error": False, "result": text},
        ])

    monkeypatch.setattr(claude_cli, "run_claude", _fake_run)
    ctx = ScanContext(
        work_dir=tmp_path, raw_dir=tmp_path, target_path=GUINEA_SRC,
        prior_findings=[_finding()],
    )
    result = asyncio.run(AiAnalysis().run(ctx))
    assert result.status.value == "ok"
    assert result.findings == []  # triage emits no new findings
    payload = result.payload
    assert payload["items"][0]["priority"] == "P0"
    assert payload["meta"]["engine"] == "claude-cli"
    assert payload["meta"]["input_findings"]["total"] == 1


def test_ai_analysis_empty_when_no_prior_findings(monkeypatch, tmp_path):
    import asyncio

    monkeypatch.setattr(claude_cli, "claude_binary", lambda: "claude")
    ctx = ScanContext(work_dir=tmp_path, target_path=GUINEA_SRC, prior_findings=[])
    result = asyncio.run(AiAnalysis().run(ctx))
    assert result.status.value == "ok"
    assert result.payload["items"] == []


def test_fallback_triage_on_unparseable_output(monkeypatch, tmp_path):
    import asyncio

    monkeypatch.setattr(claude_cli, "claude_binary", lambda: "claude")

    async def _garbage(prompt, *, cwd, timeout, add_dirs=None):
        return claude_cli.ClaudeRun(text="I could not produce JSON, sorry.",
                                    raw="...", events=[])

    monkeypatch.setattr(claude_cli, "run_claude", _garbage)
    ctx = ScanContext(work_dir=tmp_path, target_path=GUINEA_SRC, prior_findings=[_finding()])
    result = asyncio.run(AiAnalysis().run(ctx))
    assert result.status.value == "ok"
    assert "fallback" in result.payload["meta"]["engine"]
    assert result.payload["items"], "fallback must still produce items"


def _report_with_triage() -> Report:
    return Report(
        mode=Mode.STATIC, target="guinea-pig/src", generated_at="2026-06-12T00:00:00+00:00",
        duration=1.0, tools=[], findings=[], triage=_FAKE_TRIAGE,
    )


def test_claude_stream_transcript_parsing():
    # a realistic stream-json transcript: system init, an assistant tool call,
    # a tool result, and the final result event
    lines = [
        json.dumps({"type": "system", "model": "claude-x", "cwd": "/p",
                    "tools": ["Read", "Grep", "Glob"]}),
        json.dumps({"type": "assistant", "message": {"content": [
            {"type": "text", "text": "Let me inspect the sink."},
            {"type": "tool_use", "name": "Read", "input": {"file_path": "app.py"}}]}}),
        json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "content": "def run(cmd): os.system(cmd)"}]}}),
        json.dumps({"type": "result", "is_error": False, "result": "{\"summary\": \"ok\"}",
                    "total_cost_usd": 0.01, "duration_ms": 1234}),
    ]
    raw = "\n".join(lines)
    events = claude_cli._parse_events(raw)
    assert len(events) == 4
    assert claude_cli._result_text(events, raw, 0, "") == '{"summary": "ok"}'
    assert claude_cli.tool_call_count(events) == 1
    transcript = claude_cli.format_transcript(events)
    assert "[system]" in transcript and "[tool_use] Read(" in transcript
    assert "[tool_result]" in transcript and "[result]" in transcript


def test_triage_renderers_produce_valid_output():
    rep = _report_with_triage()
    j = render_triage.render_triage_json(_FAKE_TRIAGE, rep)
    assert json.loads(j)["items"][0]["location"] == "python/command_injection.py:10"
    md = render_triage.render_triage_markdown(_FAKE_TRIAGE, rep)
    assert "P0" in md and "Command injection" in md and "Real risk" in md
    h = render_triage.render_triage_html(_FAKE_TRIAGE, rep)
    assert "<!doctype html>" in h and "command_injection.py:10" in h
    console = render_triage.render_triage_console(_FAKE_TRIAGE)
    assert "P0" in console


def test_write_triage_writes_three_formats(tmp_path):
    rep = _report_with_triage()
    written = render_triage.write_triage(rep, tmp_path)
    assert set(written) == {"json", "md", "html"}
    assert (tmp_path / "triage.md").exists()
    assert (tmp_path / "triage.html").exists()
    assert (tmp_path / "triage.json").exists()


def test_write_triage_noop_without_triage(tmp_path):
    rep = Report(mode=Mode.STATIC, target="x", generated_at="t", duration=0.0, tools=[], findings=[])
    assert render_triage.write_triage(rep, tmp_path) == {}
