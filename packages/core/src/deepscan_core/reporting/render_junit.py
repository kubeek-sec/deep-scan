"""JUnit XML output of a scan - for CI test-report ingestion (GitLab, Jenkins,
GitHub, etc.).

Mapping: each deduplicated finding becomes a failing ``<testcase>`` (grouped by
location via ``classname``), each scanner that errored becomes an ``<error>``
testcase, and a clean scan emits a single passing testcase so the suite is green
rather than empty. Build-gating (which severities should fail the pipeline) stays
the caller's choice - JUnit just reports what was found.
"""

from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from ..models import Report, ToolStatus


def _failure_body(f) -> str:
    parts = [f"Severity: {f.severity.value}", f"Location: {f.location or 'unknown'}"]
    if f.tools:
        parts.append(f"Tools: {', '.join(f.tools)}")
    if f.rules:
        parts.append(f"Rules: {', '.join(f.rules)}")
    if f.cwes:
        parts.append(f"CWEs: {', '.join(f.cwes)}")
    parts.append(f"Occurrences: {f.occurrences}")
    parts.append("")
    parts.append(f.message or "")
    return escape("\n".join(parts))


def render_junit(report: Report) -> str:
    findings = report.findings
    errored = [t for t in report.tools if t.status == ToolStatus.ERROR]

    cases: list[str] = []
    for f in findings:
        classname = f.location or "unknown"
        name = f"{f.severity.value}: {(f.rules[0] if f.rules else f.message) or 'finding'}"[:160]
        cases.append(
            f"    <testcase classname={quoteattr(classname)} name={quoteattr(name)} time=\"0\">\n"
            f"      <failure message={quoteattr((f.message or 'finding')[:300])} "
            f"type={quoteattr(f.severity.value)}>{_failure_body(f)}</failure>\n"
            f"    </testcase>"
        )
    for t in errored:
        cases.append(
            f"    <testcase classname=\"scanner\" name={quoteattr(t.scanner)} "
            f"time=\"{t.duration:.3f}\">\n"
            f"      <error message={quoteattr((t.error or 'scanner error')[:300])} "
            f"type=\"scanner-error\">{escape(t.error or '')}</error>\n"
            f"    </testcase>"
        )
    if not cases:  # keep the suite non-empty so CI shows a green pass
        cases.append('    <testcase classname="deepscan" name="no findings" time="0"/>')

    tests = len(cases)
    failures = len(findings)
    errors = len(errored)
    attrs = (
        f'tests="{tests}" failures="{failures}" errors="{errors}" skipped="0" '
        f'time="{report.duration:.3f}"'
    )
    body = "\n".join(cases)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites name="deepscan" {attrs}>\n'
        f'  <testsuite name="deepscan" {attrs} timestamp={quoteattr(report.generated_at)}>\n'
        f"{body}\n"
        "  </testsuite>\n"
        "</testsuites>\n"
    )
