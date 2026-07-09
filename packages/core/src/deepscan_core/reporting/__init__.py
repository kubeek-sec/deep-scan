"""Report renderers: one ``Report`` → Markdown / JSON / HTML / SARIF / JUnit / PDF."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models import Report
from .render_html import render_html
from .render_junit import render_junit
from .render_markdown import render_markdown
from .render_pdf import render_pdf
from .render_sarif import render_sarif
from .render_triage import (
    render_triage_console,
    render_triage_html,
    render_triage_json,
    render_triage_markdown,
    write_triage,
)

_log = logging.getLogger("deepscan.reporting")

# Text formats produced by ``render`` (str output).
FORMATS = ("json", "md", "html", "sarif", "junit")
# Every downloadable format, incl. the binary PDF. Default for ``write_report``.
ALL_FORMATS = (*FORMATS, "pdf")

# Some formats use a conventional file extension that differs from the format id
# (JUnit XML is a ``.xml`` so CI globs like ``*.xml`` discover it).
_FILE_SUFFIX = {"junit": "junit.xml"}


def file_suffix(fmt: str) -> str:
    """The on-disk extension for a format ('junit.xml' for junit, else ``fmt``)."""
    return _FILE_SUFFIX.get(fmt, fmt)


def report_filename(fmt: str) -> str:
    """On-disk report filename for a format, e.g. ``report.junit.xml``."""
    return f"report.{file_suffix(fmt)}"


def render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2)
    if fmt == "md":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt == "junit":
        return render_junit(report)
    raise ValueError(f"Unknown report format {fmt!r}. Available: {', '.join(FORMATS)}")


def write_pdf(report: Report, path: Path) -> Path:
    """Write the PDF report to ``path`` (bytes)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_pdf(report))
    return path


def write_report(report: Report, out_dir: Path, formats: tuple[str, ...] = ALL_FORMATS) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for fmt in formats:
        path = out_dir / report_filename(fmt)
        if fmt == "pdf":
            # Best-effort: a PDF rendering hiccup must never lose the text reports
            # (or fail the scan that called this). The other formats are strict.
            try:
                path.write_bytes(render_pdf(report))
            except Exception:  # noqa: BLE001 - convenience format, keep going
                _log.warning("PDF report generation failed; other formats written", exc_info=True)
                continue
        else:
            path.write_text(render(report, fmt), encoding="utf-8")
        written[fmt] = path
    return written


__all__ = [
    "FORMATS", "ALL_FORMATS", "render", "render_pdf", "write_report", "write_pdf",
    "report_filename", "file_suffix",
    "render_markdown", "render_html", "render_sarif", "render_junit",
    "render_triage_json", "render_triage_markdown", "render_triage_html",
    "render_triage_console", "write_triage",
]
