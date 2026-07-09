"""``ai-analysis`` scanner - LLM triage over every other scanner's findings.

A *consumer* scanner: it runs after the producer scanners and reads their
findings from ``ctx.prior_findings``. It drives the headless Claude CLI (which
can point at a local model) to assess the **real risk** each finding carries,
deduplicate and prioritize them, and recommend remediation - emitting a
structured triage ``payload`` that the front-ends render to console and to a
dedicated triage report (Markdown / HTML / JSON).

Off by default (needs the ``claude`` CLI and a model). It never edits files or
opens PRs; it inspects code read-only.
"""

from __future__ import annotations

import json
import logging
from importlib.resources import files
from pathlib import Path

from .. import config
from ..ai import claude_cli
from ..log import get_logger
from ..models import Family, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped, ScanOutput

_DEFAULT_TIMEOUT = 1800
_MAX_FINDINGS = 300  # cap prompt size; the rest are summarized as counts

_log = get_logger("ai-analysis")


class AiAnalysis(Scanner):
    name = "ai-analysis"
    family = Family.AI
    mode = Mode.STATIC
    tool = None  # external CLI, not a managed binary
    enabled_by_default = False
    consumes_findings = True
    description = "LLM triage/prioritization of all scanners' findings (real-risk assessment)"

    @property
    def timeout(self) -> int:
        return config.timeout_for(self.name, default=_DEFAULT_TIMEOUT)

    async def _execute(self, ctx: ScanContext) -> ScanOutput:
        if ctx.target_path is None:
            raise ScannerSkipped("ai-analysis needs a directory target.")
        # Fail fast if the CLI is missing (skip rather than error).
        try:
            claude_cli.claude_binary()
        except claude_cli.ClaudeUnavailable as exc:
            raise ScannerSkipped(str(exc)) from exc

        findings = list(ctx.prior_findings)
        stats = _stats(findings)
        graph_summary = _read_graph_summary(ctx)

        if not findings:
            _log.info("no prior findings to triage - emitting empty triage")
            return ScanOutput([], payload=_empty_payload(stats, graph_summary))

        compact, truncated = _compact_findings(findings)
        prompt = (
            _resource("triage_prompt.md")
            .replace("{TARGET}", str(ctx.target_path))
            .replace("{FINDINGS_JSON}", json.dumps(compact, indent=2))
            .replace("{GRAPH_SUMMARY}", json.dumps(graph_summary, indent=2))
        )
        model = config.claude_model() or "(from claude settings/env)"
        _log.info(
            "triaging %d finding(s)%s with model %s - invoking claude (timeout %ds), "
            "this may take a while…",
            len(findings),
            f" (capped to {_MAX_FINDINGS} in prompt)" if truncated else "",
            model,
            self.timeout,
        )
        _log.debug("prompt size: %d chars", len(prompt))

        try:
            run = await claude_cli.run_claude(
                prompt, cwd=ctx.target_path, timeout=self.timeout
            )
        except claude_cli.ClaudeUnavailable as exc:
            raise ScannerSkipped(str(exc)) from exc

        result_text = run.text
        # Log + persist the *whole* conversation with Claude (prompt, every turn
        # and tool call, final result) - not just the final answer.
        transcript = claude_cli.format_transcript(run.events)
        n_tools = claude_cli.tool_call_count(run.events)
        _log.info(
            "claude returned %d chars over %d turn(s), %d tool call(s); parsing triage",
            len(result_text), len(run.events), n_tools,
        )
        level = logging.INFO if config.ai_log_conversation() else logging.DEBUG
        _log.log(level, "claude conversation with %s:\n%s", model, transcript or "(no events)")
        self.save_raw(ctx, "ai-analysis.prompt.md", prompt)
        self.save_raw(ctx, "ai-analysis.transcript.jsonl", run.raw)
        self.save_raw(ctx, "ai-analysis.transcript.txt", transcript)
        self.save_raw(ctx, "ai-analysis.result.txt", result_text)
        triage = claude_cli.extract_json_object(result_text)
        engine = "claude-cli"
        if not _looks_like_triage(triage):
            _log.warning("LLM output was not valid triage JSON - using deterministic fallback")
            triage = _fallback_triage(findings)
            engine = "heuristic-fallback (LLM output unparseable)"
        else:
            _log.info(
                "triage parsed: %d prioritized item(s), %d recommendation(s)",
                len(triage.get("items", [])),
                len(triage.get("recommendations", [])),
            )

        triage = _finalize(triage, stats, graph_summary, engine, truncated)
        return ScanOutput([], payload=triage)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _resource(name: str) -> str:
    return (files("deepscan_core.ai") / name).read_text(encoding="utf-8")


def _stats(findings: list) -> dict:
    by_sev: dict[str, int] = {s.value: 0 for s in Severity}
    by_tool: dict[str, int] = {}
    by_family: dict[str, int] = {}
    cwes: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
        by_family[f.family.value] = by_family.get(f.family.value, 0) + 1
        for c in f.cwes:
            cwes[c] = cwes.get(c, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_tool": by_tool,
        "by_family": by_family,
        "top_cwes": dict(sorted(cwes.items(), key=lambda kv: -kv[1])[:10]),
    }


def _read_graph_summary(ctx: ScanContext) -> dict:
    if ctx.raw_dir is None:
        return {}
    path = Path(ctx.raw_dir) / "analysis.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("graph_summary", {})
    except (OSError, ValueError):
        return {}


def _compact_findings(findings: list) -> tuple[list[dict], bool]:
    """Compact, severity-sorted finding list for the prompt; cap the count."""
    ordered = sorted(findings, key=lambda f: (f.severity.rank, f.location))
    truncated = len(ordered) > _MAX_FINDINGS
    out: list[dict] = []
    for f in ordered[:_MAX_FINDINGS]:
        e = f.extra or {}
        out.append({
            "tool": f.tool,
            "family": f.family.value,
            "severity": f.severity.value,
            "rule": f.rule,
            "cwes": f.cwes,
            "location": f.location,
            "message": f.message,
            "engine": e.get("engine"),
            "confidence": e.get("confidence"),
            "kind": e.get("kind"),
            "taint_chain": e.get("taint_chain"),
            "unsanitized": e.get("unsanitized"),
            "input_nearby": e.get("input_nearby"),
            "reachable_from_entrypoint": e.get("reachable_from_entrypoint"),
            "entry_point": e.get("entry_point"),
            "entry_kind": e.get("entry_kind"),
            "call_path": e.get("call_path"),
            "choke_points": e.get("choke_points"),
            "remediation": e.get("remediation"),
        })
    return out, truncated


_PRIORITY_BY_SEV = {
    Severity.CRITICAL: "P0",
    Severity.HIGH: "P1",
    Severity.MEDIUM: "P2",
    Severity.LOW: "P3",
    Severity.INFO: "P3",
}


def _fallback_triage(findings: list) -> dict:
    """Deterministic triage used only when the LLM output can't be parsed, so
    the report still has content. Priority is derived from severity alone."""
    items = []
    for f in sorted(findings, key=lambda f: (f.severity.rank, f.location)):
        e = f.extra or {}
        items.append({
            "title": f.message[:120],
            "location": f.location,
            "severity": f.severity.value,
            "priority": _PRIORITY_BY_SEV.get(f.severity, "P3"),
            "real_risk": f.message,
            "exploitability": "moderate",
            "confidence": e.get("confidence", "medium"),
            "likely_false_positive": False,
            "rationale": "Severity-based ordering (LLM triage unavailable).",
            "recommendation": e.get("remediation", "Review and remediate per the finding."),
            "cwes": f.cwes,
            "related_findings": [f"{f.tool}:{f.location}"],
        })
    return {
        "summary": (
            f"{len(items)} findings ordered by severity. The LLM triage could "
            "not be produced, so this is a deterministic fallback."
        ),
        "items": items,
        "recommendations": [],
        "deprioritized": [],
    }


def _looks_like_triage(obj) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("items"), list) and "summary" in obj


def _finalize(triage: dict, stats: dict, graph_summary: dict, engine: str, truncated: bool) -> dict:
    triage.setdefault("items", [])
    triage.setdefault("recommendations", [])
    triage.setdefault("deprioritized", [])
    triage["meta"] = {
        "engine": engine,
        "model": config.claude_model() or "(from claude settings/env)",
        "input_findings": stats,
        "graph_summary": graph_summary,
        "findings_truncated": truncated,
    }
    return triage


def _empty_payload(stats: dict, graph_summary: dict) -> dict:
    return {
        "summary": "No findings from the other scanners - nothing to triage.",
        "items": [],
        "recommendations": [],
        "deprioritized": [],
        "meta": {
            "engine": "none",
            "model": config.claude_model() or "(from claude settings/env)",
            "input_findings": stats,
            "graph_summary": graph_summary,
            "findings_truncated": False,
        },
    }
