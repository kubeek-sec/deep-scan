"""PDF report rendering (``deepscan_core.reporting.render_pdf`` + write_report)."""

from __future__ import annotations

from deepscan_core import reporting
from deepscan_core.models import (
    DedupedFinding,
    Family,
    Mode,
    Report,
    Severity,
    ToolResult,
    ToolStatus,
)
from deepscan_core.reporting import ALL_FORMATS, render_pdf, write_report


def _report() -> Report:
    finding = DedupedFinding(
        severity=Severity.HIGH,
        location="src/app.py:3",
        # Non-Latin-1 text must not crash the core-font PDF (it is sanitized).
        message="Command injection via os.system - café 漢字",
        tools=["analysis"],
        rules=["py.cmd-injection"],
        families=[Family.SAST],
        cwes=["CWE-78"],
        occurrences=2,
        fingerprints=["abc"],
    )
    tools = [
        ToolResult("analysis", Family.SAST, ToolStatus.OK, 1.2, [finding]),
        ToolResult("trivy", Family.SCA, ToolStatus.SKIPPED, 0.0, [], skip_reason="not installed"),
    ]
    return Report(
        mode=Mode.STATIC,
        target="/data/sources/adhoc/job-1",
        generated_at="2026-06-24T00:00:00+00:00",
        duration=2.5,
        tools=tools,
        findings=[finding],
        provenance={
            "origin": "adhoc",
            "source": "https://github.com/acme/x",
            "git_commit": "abc123",
            "fingerprint": "sha512:" + "de" * 64,
            "source_path": "/data/sources/adhoc/job-1",
        },
    )


def _is_pdf(data: bytes) -> bool:
    return data[:5] == b"%PDF-" and b"%%EOF" in data[-2048:]


def test_render_pdf_returns_valid_pdf_bytes():
    data = render_pdf(_report())
    assert isinstance(data, bytes)
    assert _is_pdf(data)


def test_render_pdf_without_findings_or_provenance():
    r = Report(
        mode=Mode.DYNAMIC, target="https://x.test",
        generated_at="2026-06-24T00:00:00+00:00", duration=0.1, tools=[], findings=[],
    )
    assert _is_pdf(render_pdf(r))


def test_pdf_is_in_all_formats_and_written_by_write_report(tmp_path):
    assert "pdf" in ALL_FORMATS
    written = write_report(_report(), tmp_path)
    assert written["pdf"].name == "report.pdf"
    assert _is_pdf((tmp_path / "report.pdf").read_bytes())
    # Text formats still written alongside it.
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "report.md").is_file()


def test_pdf_failure_is_best_effort(tmp_path, monkeypatch):
    def _boom(_report):
        raise RuntimeError("pdf engine exploded")

    monkeypatch.setattr(reporting, "render_pdf", _boom)
    written = write_report(_report(), tmp_path)
    # The scan's text reports must survive a PDF rendering failure.
    assert "pdf" not in written
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "report.md").is_file()
    assert not (tmp_path / "report.pdf").exists()
