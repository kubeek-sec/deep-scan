"""Render the ai-analysis triage into a dedicated report (JSON / Markdown /
HTML) and a console summary.

The triage ``payload`` produced by the ``ai-analysis`` scanner is a dict with
``summary``, ``items`` (prioritized real-risk assessments), ``recommendations``,
``deprioritized`` and ``meta``. These renderers turn it into a decision-ready
document for a human choosing what to remediate.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from ..models import Report
from .theme import PRIORITY_COLORS, chip, page

_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def _items_sorted(triage: dict) -> list[dict]:
    items = [i for i in triage.get("items", []) if isinstance(i, dict)]
    return sorted(items, key=lambda i: _PRIORITY_ORDER.get(str(i.get("priority")), 9))


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #

def render_triage_json(triage: dict, report: Report | None = None) -> str:
    out: dict[str, Any] = dict(triage)
    if report is not None:
        out["target"] = report.target
        out["generated_at"] = report.generated_at
    return json.dumps(out, indent=2)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #

def render_triage_markdown(triage: dict, report: Report | None = None) -> str:
    lines: list[str] = ["# Security triage & prioritization", ""]
    if report is not None:
        lines.append(
            f"_Target: `{report.target}` · Generated: {report.generated_at}_\n"
        )
    meta = triage.get("meta") or {}
    if meta:
        lines.append(
            f"_Engine: {meta.get('engine', '?')} · Model: {meta.get('model', '?')}_\n"
        )

    lines += ["## Summary", "", str(triage.get("summary") or "(none)"), ""]

    items = _items_sorted(triage)
    if items:
        lines += ["## Prioritized real risks", ""]
        for i in items:
            fp = " · ⚠️ likely false positive" if i.get("likely_false_positive") else ""
            lines.append(
                f"### {i.get('priority', '?')} - {i.get('title', 'Untitled')} "
                f"(`{i.get('location', '?')}`)"
            )
            lines.append("")
            lines.append(
                f"- **Severity:** {i.get('severity', '?')} · "
                f"**Exploitability:** {i.get('exploitability', '?')} · "
                f"**Confidence:** {i.get('confidence', '?')}"
                f"{fp}"
            )
            if i.get("cwes"):
                lines.append(f"- **CWE:** {', '.join(i['cwes'])}")
            lines.append(f"- **Real risk:** {i.get('real_risk', '-')}")
            lines.append(f"- **Why this priority:** {i.get('rationale', '-')}")
            lines.append(f"- **Recommendation:** {i.get('recommendation', '-')}")
            if i.get("related_findings"):
                lines.append(f"- **Related findings:** {', '.join(i['related_findings'])}")
            lines.append("")

    recs = [r for r in triage.get("recommendations", []) if r]
    if recs:
        lines += ["## Repo-wide recommendations", ""]
        lines += [f"- {r}" for r in recs]
        lines.append("")

    dep = [d for d in triage.get("deprioritized", []) if isinstance(d, dict)]
    if dep:
        lines += ["## Deprioritized / not a real risk", ""]
        for d in dep:
            lines.append(f"- `{d.get('location', '?')}` - {d.get('reason', '')}")
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

def _prio_pill(prio: str) -> str:
    color = PRIORITY_COLORS.get(prio, "#8b949e")
    return f'<span class="pill" style="background:{color}">{html.escape(prio)}</span>'


def render_triage_html(triage: dict, report: Report | None = None) -> str:
    e = html.escape
    meta = triage.get("meta") or {}

    item_html: list[str] = []
    for i in _items_sorted(triage):
        prio = str(i.get("priority", "?"))
        sev = str(i.get("severity", "info"))
        color = PRIORITY_COLORS.get(prio, "#8b949e")
        fp = '<span class="fp"> · ⚠ likely false positive</span>' if i.get("likely_false_positive") else ""
        cwes = f"<div class='kv'><b>CWE:</b> {e(', '.join(i.get('cwes') or []))}</div>" if i.get("cwes") else ""
        related = (
            f"<div class='kv'><b>Related:</b> {e(', '.join(i.get('related_findings') or []))}</div>"
            if i.get("related_findings") else ""
        )
        item_html.append(
            f"<div class='item' style='border-left-color:{color}'>"
            f"<h3>{_prio_pill(prio)} &nbsp;{e(str(i.get('title', 'Untitled')))}</h3>"
            f"<div class='kv'><code>{e(str(i.get('location', '?')))}</code> &nbsp; "
            f"{chip(sev)} &nbsp; "
            f"exploitability: <b>{e(str(i.get('exploitability', '?')))}</b> &nbsp; "
            f"confidence: <b>{e(str(i.get('confidence', '?')))}</b>{fp}</div>"
            f"{cwes}"
            f"<div class='kv'><b>Real risk:</b> {e(str(i.get('real_risk', '-')))}</div>"
            f"<div class='kv'><b>Why this priority:</b> {e(str(i.get('rationale', '-')))}</div>"
            f"<div class='kv'><b>Recommendation:</b> {e(str(i.get('recommendation', '-')))}</div>"
            f"{related}</div>"
        )

    recs = [r for r in triage.get("recommendations", []) if r]
    recs_html = (
        '<h2 class="section">Repo-wide recommendations</h2><ul>'
        + "".join(f"<li>{e(str(r))}</li>" for r in recs) + "</ul>"
        if recs else ""
    )
    dep = [d for d in triage.get("deprioritized", []) if isinstance(d, dict)]
    dep_html = (
        '<h2 class="section">Deprioritized / not a real risk</h2><ul>'
        + "".join(
            f"<li><code>{e(str(d.get('location', '?')))}</code> - {e(str(d.get('reason', '')))}</li>"
            for d in dep
        ) + "</ul>"
        if dep else ""
    )

    items_section = (
        '<h2 class="section">Prioritized real risks</h2>' + "".join(item_html)
        if item_html else '<h2 class="section">Prioritized real risks</h2>'
                          '<p class="empty">No prioritized items.</p>'
    )

    body = (
        f'<div class="panel"><h2>Summary</h2>'
        f'<div class="note">{e(str(triage.get("summary") or "(none)"))}</div></div>'
        f"{items_section}{recs_html}{dep_html}"
    )
    topmeta = ""
    if report is not None:
        topmeta = (
            f"<code>{e(report.target)}</code><br>{e(report.generated_at)} · "
            f"engine: {e(str(meta.get('engine', '?')))} · model: {e(str(meta.get('model', '?')))}"
        )
    return page("security triage", body, title="Deep Scan - security triage", topmeta=topmeta)


# --------------------------------------------------------------------------- #
# Console + file writing
# --------------------------------------------------------------------------- #

def render_triage_console(triage: dict) -> str:
    lines = ["", "AI triage - real-risk prioritization"]
    lines.append("  " + (str(triage.get("summary") or "")).strip())
    items = _items_sorted(triage)
    if not items:
        lines.append("  (no prioritized items)")
    for i in items:
        fp = " [likely FP]" if i.get("likely_false_positive") else ""
        lines.append(
            f"  {str(i.get('priority','?')):<3} {str(i.get('severity','?')):<8} "
            f"{str(i.get('location','?')):<40} {str(i.get('title',''))[:48]}{fp}"
        )
    return "\n".join(lines)


_TRIAGE_FORMATS = ("json", "md", "html")


def write_triage(report: Report, out_dir: Path, formats: tuple[str, ...] = _TRIAGE_FORMATS) -> dict[str, Path]:
    """Write triage.{json,md,html} into *out_dir* when the report carries a
    triage payload. Returns the written paths (empty if there is no triage)."""
    if not report.triage:
        return {}
    out_dir.mkdir(parents=True, exist_ok=True)
    renderers = {
        "json": render_triage_json,
        "md": render_triage_markdown,
        "html": render_triage_html,
    }
    written: dict[str, Path] = {}
    for fmt in formats:
        renderer = renderers.get(fmt)
        if renderer is None:
            continue
        path = out_dir / f"triage.{fmt}"
        path.write_text(renderer(report.triage, report), encoding="utf-8")
        written[fmt] = path
    return written
