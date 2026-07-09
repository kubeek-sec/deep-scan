from __future__ import annotations

import html

from ..fingerprint import VERIFY_COMMAND
from ..models import Report, Severity, ToolStatus
from .theme import REPORT_JS, chip, page

# Severity sort rank (high → low) used as the findings' Severity ``data-sort``.
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Provenance keys rendered (in this order) in the "Source" panel, when present.
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


def _source_panel(report: Report) -> str:
    """Where the analyzed files came from and are retained (when known)."""
    if not report.provenance:
        return ""
    e = html.escape
    rows = [
        f"<tr><th>{e(label)}</th><td><code>{e(str(val))}</code></td></tr>"
        for key, label in _PROVENANCE_LABELS
        if (val := report.provenance.get(key))
    ]
    if not rows:
        return ""
    note = ""
    if report.provenance.get("fingerprint"):
        note = (
            '<p class="muted small">Re-verify the fingerprint from the source '
            f"directory: <code>{e(VERIFY_COMMAND)}</code></p>"
        )
    return (
        '<div class="panel"><h2>Source</h2>'
        '<table class="report-table"><tbody>' + "".join(rows) + "</tbody></table>"
        + note + "</div>"
    )


def _findings_panel(report: Report) -> str:
    e = html.escape
    if not report.findings:
        return '<div class="panel"><h2>Findings</h2><p class="empty">No findings. 🎉</p></div>'

    rows = []
    for f in report.findings:
        sev = f.severity.value
        # '|'-wrapped token list so the tools dropdown can match by membership.
        tools_attr = "|" + "|".join(e(t) for t in f.tools) + "|"
        rows.append(
            f'<tr data-sev="{e(sev)}" data-tools="{tools_attr}">'
            f'<td data-sort="{_SEV_RANK.get(sev, 0)}">{chip(sev)}</td>'
            f"<td><code>{e(f.location)}</code></td>"
            f"<td>{e(f.message)}</td>"
            f"<td>{e(', '.join(f.tools))}</td>"
            f"<td>{e(', '.join(f.cwes) or '-')}</td></tr>"
        )
    sev_opts = "".join(f'<option value="{s.value}">{s.value}</option>' for s in Severity)
    all_tools = sorted({t for f in report.findings for t in f.tools})
    tool_opts = "".join(f'<option value="{e(t)}">{e(t)}</option>' for t in all_tools)
    return (
        '<div class="panel">'
        '<div class="panel-head">'
        '<h2>Findings <span class="count" data-count="findings-table"></span></h2>'
        '<div class="toolbar">'
        '<input type="search" data-filter="findings-table" placeholder="Filter findings…">'
        '<select data-filter-table="findings-table" data-filter-attr="sev">'
        f'<option value="">All severities</option>{sev_opts}</select>'
        '<select data-filter-table="findings-table" data-filter-attr="tools" data-filter-list>'
        f'<option value="">All tools</option>{tool_opts}</select>'
        "</div></div>"
        '<div class="table-wrap">'
        '<table id="findings-table" class="report-table" data-default-col="0">'
        "<thead><tr><th data-desc>Severity</th><th>Location</th><th>Finding</th>"
        "<th>Tools</th><th>CWE</th></tr></thead>"
        "<tbody>" + "".join(rows)
        + '<tr class="norows" hidden><td colspan="5">No findings match the filter.</td></tr>'
        "</tbody></table></div></div>"
    )


def _scanners_panel(report: Report) -> str:
    e = html.escape
    rows = []
    for t in report.tools:
        note = t.error or t.skip_reason or ""
        ok = t.status == ToolStatus.OK
        count = str(len(t.findings)) if ok else "-"
        count_sort = len(t.findings) if ok else -1
        status = t.status.value
        rows.append(
            f'<tr data-status="{e(status)}">'
            f"<td>{e(t.scanner)}</td><td>{e(t.family.value)}</td>"
            f'<td><span class="badge {status}">{e(status)}</span></td>'
            f'<td data-sort="{count_sort}">{count}</td>'
            f'<td data-sort="{t.duration:.4f}">{t.duration:.1f}s</td>'
            f"<td class='muted'>{e(note)}</td></tr>"
        )
    status_opts = "".join(
        f'<option value="{s}">{s}</option>'
        for s in sorted({t.status.value for t in report.tools})
    )
    return (
        '<div class="panel">'
        '<div class="panel-head">'
        '<h2>Scanners <span class="count" data-count="tools-table"></span></h2>'
        '<div class="toolbar">'
        '<input type="search" data-filter="tools-table" placeholder="Filter scanners…">'
        '<select data-filter-table="tools-table" data-filter-attr="status">'
        f'<option value="">All statuses</option>{status_opts}</select>'
        "</div></div>"
        '<div class="table-wrap">'
        '<table id="tools-table" class="report-table" data-default-col="0">'
        "<thead><tr><th>Scanner</th><th>Family</th><th>Status</th>"
        "<th data-desc>Findings</th><th data-desc>Duration</th>"
        '<th class="nosort">Note</th></tr></thead>'
        "<tbody>" + "".join(rows)
        + '<tr class="norows" hidden><td colspan="6">No scanners match the filter.</td></tr>'
        "</tbody></table></div></div>"
    )


def render_html(report: Report) -> str:
    e = html.escape

    totals = report.severity_totals
    stats = "".join(
        f'<div class="statbox">{chip(s.value)}<b>{totals[s.value]}</b></div>' for s in Severity
    )
    body = (
        f'<div class="panel"><h2>Summary</h2><div class="summary">{stats}</div></div>'
        f"{_source_panel(report)}"
        f"{_findings_panel(report)}"
        f"{_scanners_panel(report)}"
    )
    topmeta = (
        f"<code>{e(report.target)}</code><br>{e(report.generated_at)} · "
        f"{report.duration:.1f}s · {len(report.findings)} findings"
    )
    return page(
        f"{report.mode.value} scan report", body, topmeta=topmeta, script=REPORT_JS
    )
