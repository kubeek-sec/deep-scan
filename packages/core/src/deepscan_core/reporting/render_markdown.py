from __future__ import annotations

from ..fingerprint import VERIFY_COMMAND
from ..models import Report, Severity, ToolStatus

_SEVERITY_ICON = {
    "critical": "🟣",
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡",
    "info": "🔵",
}

# Provenance keys rendered (in this order) in the "Source" section, when present.
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


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# Deep Scan report - {report.mode.value} scan")
    lines.append("")
    lines.append(f"- **Target:** `{report.target}`")
    lines.append(f"- **Generated:** {report.generated_at}")
    lines.append(f"- **Duration:** {report.duration:.1f}s")
    lines.append("")

    if report.provenance:
        lines.append("## Source")
        lines.append("")
        for key, label in _PROVENANCE_LABELS:
            val = report.provenance.get(key)
            if val:
                lines.append(f"- **{label}:** `{val}`")
        if report.provenance.get("fingerprint"):
            lines.append("")
            lines.append(
                "Re-verify the fingerprint from the source directory with: "
                f"`{VERIFY_COMMAND}`"
            )
        lines.append("")

    totals = report.severity_totals
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Findings |")
    lines.append("|---|---|")
    for sev in Severity:
        lines.append(f"| {_SEVERITY_ICON[sev.value]} {sev.value} | {totals[sev.value]} |")
    lines.append(f"| **total (deduplicated)** | **{len(report.findings)}** |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not report.findings:
        lines.append("No findings. 🎉")
    else:
        lines.append("| Severity | Location | Finding | Tools | CWE |")
        lines.append("|---|---|---|---|---|")
        for f in report.findings:
            message = f.message.replace("|", "\\|").replace("\n", " ")
            if len(message) > 160:
                message = message[:157] + "..."
            lines.append(
                f"| {_SEVERITY_ICON[f.severity.value]} {f.severity.value} "
                f"| `{f.location}` | {message} "
                f"| {', '.join(f.tools)} | {', '.join(f.cwes) or '-'} |"
            )
    lines.append("")

    lines.append("## Scanners")
    lines.append("")
    lines.append("| Scanner | Family | Status | Findings | Duration | Note |")
    lines.append("|---|---|---|---|---|---|")
    for t in report.tools:
        note = t.error or t.skip_reason or ""
        note = note.replace("|", "\\|").replace("\n", " ")[:120]
        count = len(t.findings) if t.status == ToolStatus.OK else "-"
        lines.append(
            f"| {t.scanner} | {t.family.value} | {t.status.value} "
            f"| {count} | {t.duration:.1f}s | {note} |"
        )
    lines.append("")
    return "\n".join(lines)
