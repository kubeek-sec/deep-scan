"""Catalog + registration + skip tests for the added secret scanners
(nosey_parker, titus, betterleaks, kingfisher). No binaries required."""

from __future__ import annotations

import asyncio

import pytest

from deepscan_core import registry
from deepscan_core.install.catalog import TOOLS, ToolKind
from deepscan_core.models import Family
from deepscan_core.scanners import ScanContext

_NEW = ["nosey_parker", "titus", "betterleaks", "kingfisher"]


def test_new_secret_scanners_registered():
    for name in _NEW:
        s = registry.REGISTRY[name]
        assert s.family is Family.SECRET and s.tool == name


@pytest.mark.parametrize("name", _NEW)
def test_catalog_entry_valid(name):
    spec = TOOLS[name]
    assert spec.kind in (ToolKind.ARCHIVE, ToolKind.BINARY)
    if spec.kind is ToolKind.ARCHIVE:
        assert spec.archive_member  # binary path inside the archive
    for _key, (url, sha) in spec.artifacts.items():
        assert url.startswith("https://") and len(sha) == 64


@pytest.mark.parametrize("name", _NEW)
def test_skips_when_tool_not_installed(name, tmp_path, monkeypatch):
    # Force "not installed" regardless of the host, then expect a clean skip.
    monkeypatch.setattr("deepscan_core.scanners.base.tool_path", lambda _n: None)
    ctx = ScanContext(work_dir=tmp_path, target_path=tmp_path)
    result = asyncio.run(registry.REGISTRY[name].run(ctx))
    assert result.status.value == "skipped"
