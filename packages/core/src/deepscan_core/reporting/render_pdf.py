"""Render a ``Report`` to a PDF (bytes), built programmatically with fpdf2.

Unlike the HTML/Markdown renderers there is no themed template - the layout is
drawn directly so the PDF needs no browser or system libraries (pure Python),
which matters in the hardened, slim worker container. Core fonts are Latin-1
only, so all text is sanitized; the JSON/MD/HTML formats keep full Unicode.
"""

from __future__ import annotations

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

from ..fingerprint import VERIFY_COMMAND
from ..models import Report, Severity, ToolStatus

# Same provenance fields/order as the HTML & Markdown "Source" section.
_PROVENANCE_LABELS = (
    ("origin", "Origin"),
    ("surface", "Surface"),
    ("source", "Source"),
    ("source_id", "Source ID"),
    ("git_commit", "Commit"),
    ("fingerprint", "Fingerprint"),
    ("upload_id", "Upload ID"),
    ("source_path", "Retained files"),
)

_HEADINGS_STYLE = FontFace(
    emphasis="BOLD", color=(255, 255, 255), fill_color=(37, 99, 235)  # white on blue
)


def _safe(text: object) -> str:
    """Latin-1-safe text (fpdf2 core fonts only encode Latin-1)."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def _heading(pdf: FPDF, text: str) -> None:
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)


def _kv(pdf: FPDF, label: str, value: object) -> None:
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(32, 5, _safe(label), new_x=XPos.END, new_y=YPos.TOP)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_x(pdf.l_margin + 32)
    pdf.multi_cell(0, 5, _safe(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _table(pdf: FPDF, headings: list[str], rows: list[list[str]], widths: tuple[int, ...]) -> None:
    pdf.set_font("Helvetica", "", 8)
    with pdf.table(
        col_widths=widths,
        headings_style=_HEADINGS_STYLE,
        text_align="LEFT",
        line_height=5,
    ) as table:
        head = table.row()
        for h in headings:
            head.cell(_safe(h))
        for r in rows:
            row = table.row()
            for c in r:
                row.cell(_safe(c))


def render_pdf(report: Report) -> bytes:
    """Return the report as a PDF document (bytes)."""
    pdf = FPDF()
    pdf.set_title(f"Deep Scan report - {report.mode.value} scan")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _safe(f"Deep Scan report - {report.mode.value} scan"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    for label, value in (
        ("Target", report.target),
        ("Generated", report.generated_at),
        ("Duration", f"{report.duration:.1f}s"),
    ):
        _kv(pdf, label, value)

    if report.provenance:
        _heading(pdf, "Source")
        for key, label in _PROVENANCE_LABELS:
            value = report.provenance.get(key)
            if value:
                _kv(pdf, label, value)
        if report.provenance.get("fingerprint"):
            pdf.set_font("Helvetica", "I", 7)
            pdf.multi_cell(0, 4, _safe(f"Re-verify from the source directory: {VERIFY_COMMAND}"),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    totals = report.severity_totals
    _heading(pdf, "Summary")
    _table(
        pdf,
        ["Severity", "Findings"],
        [[sev.value, str(totals[sev.value])] for sev in Severity]
        + [["total (deduplicated)", str(len(report.findings))]],
        widths=(60, 30),
    )

    _heading(pdf, "Findings")
    if not report.findings:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, "No findings.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        _table(
            pdf,
            ["Severity", "Location", "Finding", "Tools", "CWE"],
            [
                [
                    f.severity.value,
                    f.location,
                    f.message,
                    ", ".join(f.tools),
                    ", ".join(f.cwes) or "-",
                ]
                for f in report.findings
            ],
            widths=(14, 34, 60, 24, 16),
        )

    _heading(pdf, "Scanners")
    _table(
        pdf,
        ["Scanner", "Family", "Status", "Findings", "Duration", "Note"],
        [
            [
                t.scanner,
                t.family.value,
                t.status.value,
                str(len(t.findings)) if t.status == ToolStatus.OK else "-",
                f"{t.duration:.1f}s",
                (t.error or t.skip_reason or ""),
            ]
            for t in report.tools
        ],
        widths=(26, 18, 16, 16, 16, 56),
    )

    return bytes(pdf.output())
