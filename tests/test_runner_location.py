"""Finding locations are reported relative to the scanned tree, never with the
transient RAM-staging scan-root prefix (e.g. ``/ramscan/deepscan-scan/<hash>/``).
"""

from __future__ import annotations

import asyncio

import pytest

from deepscan_core import registry, runner
from deepscan_core.models import Family, Finding, Mode, Severity
from deepscan_core.runner import _relativize_location, run_scan
from deepscan_core.scanners import ScanContext, Scanner


def test_relativize_strips_scan_root():
    roots = ["/ramscan/deepscan-scan/abc123"]
    assert (
        _relativize_location("/ramscan/deepscan-scan/abc123/core/http/x.rs:15", roots)
        == "core/http/x.rs:15"
    )


def test_relativize_handles_file_uri():
    roots = ["/ramscan/deepscan-scan/abc123"]
    assert (
        _relativize_location("file:///ramscan/deepscan-scan/abc123/a/b.py:7", roots)
        == "a/b.py:7"
    )


def test_relativize_leaves_other_locations_untouched():
    roots = ["/ramscan/deepscan-scan/abc123"]
    # already relative, package spec, URL - all returned unchanged
    assert _relativize_location("core/http/x.rs:15", roots) == "core/http/x.rs:15"
    assert _relativize_location("pip:requests@2.0", roots) == "pip:requests@2.0"
    assert _relativize_location("https://kubeek.com/info/o/r/x", roots) == "https://kubeek.com/info/o/r/x"


def test_relativize_is_idempotent():
    roots = ["/ramscan/deepscan-scan/abc123"]
    once = _relativize_location("/ramscan/deepscan-scan/abc123/a.rs:1", roots)
    assert _relativize_location(once, roots) == once == "a.rs:1"


def test_run_scan_relativizes_absolute_finding_paths(tmp_path, monkeypatch):
    """A scanner that emits an absolute path (as tools handed an absolute target
    do) has it rewritten relative to the scan root in the final report."""

    class _AbsPathScanner(Scanner):
        name = "fake-abs"
        family = Family.SAST
        mode = Mode.STATIC

        async def _execute(self, ctx: ScanContext):
            abs_loc = f"{ctx.target_path}/core/http/src/uri/absolute.rs:15"
            return [
                Finding(
                    tool=self.name,
                    family=self.family,
                    rule="demo",
                    severity=Severity.HIGH,
                    message="absolute path leaked",
                    location=abs_loc,
                )
            ]

    monkeypatch.setitem(registry.REGISTRY, "fake-abs", _AbsPathScanner())

    report = asyncio.run(run_scan(str(tmp_path), scanners=["fake-abs"]))

    locations = [f.location for f in report.findings]
    assert locations == ["core/http/src/uri/absolute.rs:15"]
    # the raw per-tool view is normalized too
    tool_result = next(t for t in report.tools if t.scanner == "fake-abs")
    assert tool_result.findings[0].location == "core/http/src/uri/absolute.rs:15"
