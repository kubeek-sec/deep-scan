"""Normalized data model shared by every Deep Scan front-end (MCP, CLI, API).

Every scanner, whatever its native output format, is parsed into ``Finding``
objects; a scan produces one ``ToolResult`` per scanner and a single ``Report``
holding the deduplicated view.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_string(cls, raw: str | None, default: "Severity | None" = None) -> "Severity":
        if raw:
            value = raw.strip().lower()
            aliases = {
                "error": cls.HIGH,
                "warning": cls.MEDIUM,
                "warn": cls.MEDIUM,
                "note": cls.LOW,
                "none": cls.INFO,
                "informational": cls.INFO,
                "moderate": cls.MEDIUM,
                "important": cls.HIGH,
            }
            if value in cls._value2member_map_:
                return cls(value)
            if value in aliases:
                return aliases[value]
        return default or cls.MEDIUM

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Family(str, enum.Enum):
    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"
    IAC = "iac"
    LICENSE = "license"
    PIPELINE = "pipeline"
    DAST = "dast"
    MALWARE = "malware"  # virus/malware signatures (ClamAV)
    ANALYSIS = "analysis"  # code-graph + taint/sanitization analysis (no AI)
    AI = "ai"  # LLM-driven triage/prioritization over other scanners' findings


class Mode(str, enum.Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"


class ToolStatus(str, enum.Enum):
    OK = "ok"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class Finding:
    """One normalized finding from one scanner."""

    tool: str
    family: Family
    rule: str
    severity: Severity
    message: str
    location: str  # "path/to/file.py:42", "package:name@version" or a URL
    cwes: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable identity: survives re-scans, ignores volatile detail."""
        content = "|".join(
            [self.tool, self.rule, _normalize(self.location), _normalize(self.message)]
        )
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "tool": self.tool,
            "family": self.family.value,
            "rule": self.rule,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location,
            "cwes": self.cwes,
            "extra": self.extra,
        }


@dataclass
class DedupedFinding:
    """A finding after cross-tool deduplication."""

    severity: Severity
    location: str
    message: str
    tools: list[str]
    rules: list[str]
    families: list[str]
    cwes: list[str]
    occurrences: int
    fingerprints: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "location": self.location,
            "message": self.message,
            "tools": self.tools,
            "rules": self.rules,
            "families": self.families,
            "cwes": self.cwes,
            "occurrences": self.occurrences,
            "fingerprints": self.fingerprints,
        }


@dataclass
class ToolResult:
    scanner: str
    family: Family
    status: ToolStatus
    duration: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    skip_reason: str | None = None
    raw_output_path: str | None = None
    # Optional structured output beyond findings (e.g. the ai-analysis triage:
    # prioritized real-risk items, recommendations). Surfaced on the Report.
    payload: dict[str, Any] | None = None

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "family": self.family.value,
            "status": self.status.value,
            "duration": round(self.duration, 2),
            "findings": [f.to_dict() for f in self.findings],
            "severity_counts": self.severity_counts,
            "error": self.error,
            "skip_reason": self.skip_reason,
            "raw_output_path": self.raw_output_path,
            "payload": self.payload,
        }


@dataclass
class Report:
    mode: Mode
    target: str
    generated_at: str
    duration: float
    tools: list[ToolResult]
    findings: list[DedupedFinding]
    # Cross-cutting triage produced by the ai-analysis consumer scanner, if it
    # ran: prioritized real-risk items, recommendations and a human summary.
    triage: dict[str, Any] | None = None
    # Where the analyzed files came from and are retained (origin, logical source,
    # retained ``source_path``, upload_id, revision …). Set by the job worker, not
    # the core library; surfaced in the report meta and the "Source" section.
    provenance: dict[str, Any] | None = None

    @property
    def severity_totals(self) -> dict[str, int]:
        totals = {s.value: 0 for s in Severity}
        for f in self.findings:
            totals[f.severity.value] += 1
        return totals

    def to_dict(self) -> dict[str, Any]:
        raw_count = sum(len(t.findings) for t in self.tools)
        meta: dict[str, Any] = {
            "mode": self.mode.value,
            "target": self.target,
            "generated_at": self.generated_at,
            "duration_seconds": round(self.duration, 2),
            "schema_version": "1.0",
        }
        if self.provenance:
            meta["provenance"] = self.provenance
        return {
            "meta": meta,
            "summary": {
                "tools_run": sum(1 for t in self.tools if t.status == ToolStatus.OK),
                "tools_skipped": sum(1 for t in self.tools if t.status == ToolStatus.SKIPPED),
                "tools_error": sum(1 for t in self.tools if t.status == ToolStatus.ERROR),
                "raw_findings": raw_count,
                "deduplicated_findings": len(self.findings),
                "duplicates_removed": raw_count - len(self.findings),
                "severity_totals": self.severity_totals,
            },
            "tools": [t.to_dict() for t in self.tools],
            "findings": [f.to_dict() for f in self.findings],
            "triage": self.triage,
        }


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())
