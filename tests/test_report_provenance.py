"""Report provenance: the 'Source' block in md/html and meta.provenance in json.

No database needed - exercises the core model + renderers directly.
"""

from __future__ import annotations

from deepscan_core.models import Mode, Report
from deepscan_core.reporting import render_html, render_markdown


def _report(**kw) -> Report:
    return Report(
        mode=Mode.STATIC,
        target="/dev/shm/deepscan-scan/abc",   # internal/RAM path; provenance is the truth
        generated_at="2026-01-01T00:00:00+00:00",
        duration=1.0,
        tools=[],
        findings=[],
        **kw,
    )


def test_provenance_nested_in_json_meta():
    prov = {
        "origin": "adhoc",
        "source": "https://github.com/acme/x",
        "source_path": "/data/sources/adhoc/job-1",
    }
    assert _report(provenance=prov).to_dict()["meta"]["provenance"] == prov


def test_no_provenance_omits_meta_key():
    assert "provenance" not in _report().to_dict()["meta"]


def test_markdown_source_section():
    prov = {
        "origin": "discovery",
        "source": "acme/x",
        "source_path": "/data/sources/discovery/job-9",
        "git_commit": "abc123def456",
        "fingerprint": "sha512:deadbeef",
    }
    md = render_markdown(_report(provenance=prov))
    assert "## Source" in md
    assert "/data/sources/discovery/job-9" in md
    assert "**Commit:**" in md and "abc123def456" in md
    assert "**Fingerprint:**" in md and "sha512:deadbeef" in md
    # The fingerprint comes with the documented re-verification command.
    assert "find . -type f -print0" in md
    # Back-compat: no provenance → no Source section.
    assert "## Source" not in render_markdown(_report())


def test_html_source_panel():
    prov = {
        "origin": "adhoc",
        "upload_id": "deadbeef",
        "source_path": "/data/uploads/deadbeef",
        "fingerprint": "sha512:cafe",
    }
    html = render_html(_report(provenance=prov))
    assert "<h2>Source</h2>" in html
    assert "deadbeef" in html
    assert "find . -type f -print0" in html   # re-verification command shown
    assert "<h2>Source</h2>" not in render_html(_report())
