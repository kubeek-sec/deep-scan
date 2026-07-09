"""Cross-tool deduplication of normalized findings.

Key: normalized ``(location, message)``. Findings merging keeps the highest
severity, unions tools/rules/CWEs and counts occurrences. Distinct locations
are never merged, so two secrets in two files always stay two findings.
"""

from __future__ import annotations

from .models import DedupedFinding, Finding


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


def deduplicate(findings: list[Finding]) -> list[DedupedFinding]:
    merged: dict[tuple[str, str], DedupedFinding] = {}
    for f in findings:
        key = (_norm(f.location), _norm(f.message))
        entry = merged.get(key)
        if entry is None:
            merged[key] = DedupedFinding(
                severity=f.severity,
                location=f.location,
                message=f.message,
                tools=[f.tool],
                rules=[f.rule],
                families=[f.family.value],
                cwes=list(f.cwes),
                occurrences=1,
                fingerprints=[f.fingerprint],
            )
            continue
        if f.severity.rank < entry.severity.rank:
            entry.severity = f.severity
        for collection, value in (
            (entry.tools, f.tool),
            (entry.rules, f.rule),
            (entry.families, f.family.value),
            (entry.fingerprints, f.fingerprint),
        ):
            if value not in collection:
                collection.append(value)
        for cwe in f.cwes:
            if cwe not in entry.cwes:
                entry.cwes.append(cwe)
        entry.occurrences += 1
    return sorted(merged.values(), key=lambda d: (d.severity.rank, d.location, d.message))
