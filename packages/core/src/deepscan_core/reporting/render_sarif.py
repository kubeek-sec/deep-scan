"""Merged SARIF 2.1.0 output of the deduplicated findings - one run, driver
"deepscan", original tool names preserved in result properties."""

from __future__ import annotations

import json

from ..models import Report, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(report: Report) -> str:
    rules_seen: dict[str, dict] = {}
    results = []
    for f in report.findings:
        rule_id = f.rules[0] if f.rules else "deepscan-finding"
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "properties": {"tags": list(f.cwes)},
            }
        file_part, _, line_part = f.location.partition(":")
        region = {}
        if line_part.isdigit():
            region = {"region": {"startLine": int(line_part)}}
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_part},
                            **region,
                        }
                    }
                ],
                "properties": {
                    "deepscan/severity": f.severity.value,
                    "deepscan/tools": f.tools,
                    "deepscan/families": f.families,
                    "deepscan/cwes": f.cwes,
                    "deepscan/occurrences": f.occurrences,
                },
                "fingerprints": {"deepscan/v1": f.fingerprints[0] if f.fingerprints else ""},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deepscan",
                        "informationUri": "https://github.com/deep-scan",
                        "rules": list(rules_seen.values()),
                    }
                },
                "properties": {
                    "deepscan/mode": report.mode.value,
                    "deepscan/target": report.target,
                    "deepscan/generated_at": report.generated_at,
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
