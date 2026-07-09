"""SARIF 2.1.0 parsing into normalized findings."""

from __future__ import annotations

import json
import re
from typing import Any

from .models import Family, Finding, Severity

_LEVEL_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

_CWE_RE = re.compile(r"(?:CWE|cwe)[-_:]?(\d+)")


def parse_sarif(text: str, tool: str, family: Family) -> list[Finding]:
    """Parse a SARIF document into findings. Raises ValueError on bad JSON."""
    doc = json.loads(text)
    findings: list[Finding] = []
    for run in doc.get("runs") or []:
        rules_index = _index_rules(run)
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or "unknown-rule"
            rule_meta = rules_index.get(rule_id, {})
            severity = _severity_for(result, rule_meta)
            message = (result.get("message") or {}).get("text") or rule_id
            location = _location_for(result)
            cwes = _cwes_for(rule_id, rule_meta, message)
            findings.append(
                Finding(
                    tool=tool,
                    family=family,
                    rule=rule_id,
                    severity=severity,
                    message=message.strip(),
                    location=location,
                    cwes=cwes,
                )
            )
    return findings


def _index_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    index: dict[str, dict[str, Any]] = {}
    for rule in rules:
        rule_id = rule.get("id")
        if rule_id:
            index[rule_id] = rule
    return index


def _severity_for(result: dict[str, Any], rule_meta: dict[str, Any]) -> Severity:
    properties = rule_meta.get("properties") or {}
    sec_sev = properties.get("security-severity")
    if sec_sev is not None:
        try:
            return Severity.from_cvss(float(sec_sev))
        except (TypeError, ValueError):
            pass
    level = result.get("level")
    if level in _LEVEL_MAP:
        return _LEVEL_MAP[level]
    for key in ("severity", "problem.severity"):
        raw = properties.get(key)
        if raw:
            return Severity.from_string(str(raw))
    default_level = (rule_meta.get("defaultConfiguration") or {}).get("level")
    if default_level in _LEVEL_MAP:
        return _LEVEL_MAP[default_level]
    return Severity.MEDIUM


def _location_for(result: dict[str, Any]) -> str:
    for loc in result.get("locations") or []:
        physical = loc.get("physicalLocation") or {}
        uri = ((physical.get("artifactLocation") or {}).get("uri")) or ""
        line = (physical.get("region") or {}).get("startLine")
        if uri:
            return f"{uri}:{line}" if line else uri
    return "unknown"


def _cwes_for(rule_id: str, rule_meta: dict[str, Any], message: str) -> list[str]:
    cwes: set[str] = set()
    properties = rule_meta.get("properties") or {}
    tags = properties.get("tags") or []
    for blob in [rule_id, message, " ".join(str(t) for t in tags)]:
        for match in _CWE_RE.finditer(blob):
            cwes.add(f"CWE-{match.group(1)}")
    for rel in rule_meta.get("relationships") or []:
        target_id = (rel.get("target") or {}).get("id") or ""
        for match in _CWE_RE.finditer(target_id):
            cwes.add(f"CWE-{match.group(1)}")
    return sorted(cwes)
