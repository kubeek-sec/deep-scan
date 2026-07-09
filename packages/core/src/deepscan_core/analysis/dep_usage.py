"""Reachable-dependency analysis: correlate SCA findings with the code graph.

SCA scanners (trivy, osv-scanner) report *which dependencies have known
vulnerabilities*. The code graph's ``imports`` edges tell us *which libraries the
code actually imports and where*. Crossing the two answers the question that
decides whether a CVE matters in practice:

    "Is the vulnerable dependency actually used by this code - and is that usage
     reachable from an entry point - or is it merely declared / transitive?"

For each SCA finding we report a verdict (``used`` / ``not-found``) plus, for
used ones, the importing files and whether any is reachable from an entry point.
A declared-but-unimported dependency is downgraded; a reachable one keeps its
weight. The match is a heuristic (import name ↔ package name, with a small alias
table), so verdicts carry a confidence and never silently hide a CVE.

Pure graph + string matching; nothing is executed.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..log import get_logger
from ..models import Family, Finding, Severity
from .reachability import CallGraph

_log = get_logger("analysis")

# import name → alternative package spellings seen in SCA reports.
_ALIAS: dict[str, set[str]] = {
    "yaml": {"pyyaml"}, "bs4": {"beautifulsoup4"}, "sklearn": {"scikit-learn"},
    "dateutil": {"python-dateutil"}, "pil": {"pillow"}, "cv2": {"opencv-python", "opencv"},
    "jwt": {"pyjwt"}, "dotenv": {"python-dotenv"}, "serial": {"pyserial"},
    "openssl": {"pyopenssl"}, "crypto": {"pycryptodome", "pycrypto"},
    "google": {"protobuf", "google-cloud"},
}

# Standard-library / runtime modules that are never third-party SCA packages.
_STDLIB = {
    "os", "sys", "re", "io", "json", "math", "time", "abc", "csv", "ast", "gc",
    "subprocess", "pathlib", "typing", "logging", "functools", "itertools",
    "collections", "datetime", "asyncio", "http", "urllib", "socket", "struct",
    "hashlib", "base64", "fs", "path", "util", "crypto", "events", "stream",
    "buffer", "child_process", "cluster", "net", "tls", "url", "querystring",
}

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _downgrade(sev: Severity, steps: int) -> Severity:
    idx = min(len(_SEV_ORDER) - 1, _SEV_ORDER.index(sev) + steps)
    return _SEV_ORDER[idx]


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _import_map(extraction: dict) -> dict[str, set[str]]:
    """Top-level imported name → set of source files importing it."""
    nodes_by_id = {n.get("id"): n for n in extraction.get("nodes", []) if isinstance(n, dict)}
    libs: dict[str, set[str]] = {}
    for e in extraction.get("edges", []):
        if not isinstance(e, dict) or e.get("relation") != "imports":
            continue
        target = str(e.get("target") or "")
        top = re.split(r"[./\\]", target)[0].strip()
        if not top or len(top) < 3 or top.lower() in _STDLIB:
            continue
        src = nodes_by_id.get(e.get("source"), {})
        file = src.get("source_file") or e.get("source_file") or ""
        libs.setdefault(top, set()).add(str(file))
    return libs


def _candidates(lib: str) -> set[str]:
    n = _norm(lib)
    out = {n, n.replace("-", "")}
    out |= {_norm(a) for a in _ALIAS.get(n, set())}
    return {c for c in out if c}


def analyze(target: Path, work_dir: Path, sca_findings: list[Finding]) -> list[Finding]:
    if not sca_findings:
        return []
    try:
        from graphoofy.extract import collect_files, extract

        files = collect_files(target)
        extraction = extract(files, cache_root=work_dir, parallel=False)
    except Exception as exc:  # noqa: BLE001
        _log.debug("dep-usage: graph build failed: %s", exc)
        return []

    libs = _import_map(extraction)
    try:
        reachable_files = CallGraph(extraction).reachable_files()
    except Exception:  # noqa: BLE001
        reachable_files = set()

    # Precompute candidate tokens per imported lib for matching.
    lib_tokens = {lib: _candidates(lib) for lib in libs}

    out: list[Finding] = []
    for f in sca_findings:
        text = f"{f.rule} {f.message} {f.location}".lower()
        matched = [
            lib for lib, toks in lib_tokens.items()
            if any(re.search(r"\b" + re.escape(t) + r"\b", text) for t in toks)
        ]
        if matched:
            used_files = sorted({fl for lib in matched for fl in libs[lib] if fl})
            reachable = any(fl in reachable_files for fl in used_files)
            sev = f.severity if reachable else _downgrade(f.severity, 1)
            conf = "high" if reachable else "medium"
            where = ", ".join(used_files[:5]) + (" …" if len(used_files) > 5 else "")
            msg = (
                f"Reachable vulnerable dependency: import '{', '.join(sorted(set(matched)))}' "
                f"is used in the scanned code ({len(used_files)} file(s))"
                + (" and reaches an entry point" if reachable
                   else " but is not reached from any entry point")
                + f" - re-evaluate {f.rule}"
            )
            verdict = "used-reachable" if reachable else "used-unreachable"
            extra = {
                "engine": "analysis/dep-usage", "verdict": verdict, "confidence": conf,
                "matched_imports": sorted(set(matched)), "used_by": used_files[:20],
                "reachable_from_entry": reachable, "sca_tool": f.tool,
                "sca_severity": f.severity.value, "where": where,
            }
        else:
            sev = _downgrade(f.severity, 2)
            msg = (
                f"SCA-flagged dependency for {f.rule} was not matched to any import in "
                "the scanned source - likely unused, transitive, or dynamically loaded; "
                "verify before prioritizing"
            )
            extra = {
                "engine": "analysis/dep-usage", "verdict": "not-found", "confidence": "low",
                "matched_imports": [], "used_by": [], "reachable_from_entry": False,
                "sca_tool": f.tool, "sca_severity": f.severity.value,
            }
        out.append(Finding(
            tool="reachable-deps", family=Family.ANALYSIS, rule=f.rule, severity=sev,
            message=msg, location=f.location, cwes=f.cwes, extra=extra,
        ))
    return out
