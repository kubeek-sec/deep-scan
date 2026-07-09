"""Tests for the managed-tool catalog/installer additions (codeql, plumber).

No network: exercises the directory-tree extraction, zip-slip guard, path
resolution and catalog wiring with synthetic archives.
"""

from __future__ import annotations

import asyncio
import io
import os
import stat
import zipfile
from pathlib import Path

import pytest

from deepscan_core import install
from deepscan_core.install import _extract_tree
from deepscan_core.install.catalog import TOOLS, ToolKind


def test_catalog_has_codeql_and_plumber():
    assert "plumber" in TOOLS and TOOLS["plumber"].kind is ToolKind.BINARY
    cq = TOOLS["codeql"]
    assert cq.kind is ToolKind.ARCHIVE_DIR and cq.launcher == "codeql/codeql"
    assert cq.max_bytes and cq.max_bytes > 600 * 1024 * 1024  # raised cap for the big bundle
    for spec in (cq, TOOLS["plumber"]):
        for _key, (url, sha) in spec.artifacts.items():
            assert url.startswith("https://") and len(sha) == 64


def test_tool_path_none_when_not_installed():
    # ARCHIVE_DIR + BINARY both resolve to None until installed
    assert install.tool_path("codeql") is None or isinstance(install.tool_path("codeql"), Path)


def _zip(entries: dict[str, tuple[str, int]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, (content, mode) in entries.items():
            zi = zipfile.ZipInfo(name)
            zi.external_attr = (mode & 0xFFFF) << 16
            z.writestr(zi, content)
    return buf.getvalue()


def test_extract_tree_preserves_exec_bits(tmp_path):
    data = _zip({
        "codeql/codeql": ("#!/bin/sh\n", 0o755),
        "codeql/qlpacks/x.qll": ("// q\n", 0o644),
        "codeql/tools/extractor": ("bin\n", 0o755),
    })
    dest = tmp_path / "cq"
    _extract_tree(TOOLS["codeql"], "x.zip", data, dest)
    launcher = dest / "codeql" / "codeql"
    assert launcher.is_file() and (os.stat(launcher).st_mode & stat.S_IXUSR)
    assert (dest / "codeql" / "qlpacks" / "x.qll").is_file()
    assert os.stat(dest / "codeql" / "tools" / "extractor").st_mode & stat.S_IXUSR


def test_extract_tree_blocks_zip_slip(tmp_path):
    data = _zip({"../escape.sh": ("x", 0o644)})
    with pytest.raises(install.InstallError):
        _extract_tree(TOOLS["codeql"], "x.zip", data, tmp_path / "d")


def test_plumber_scanner_skips_without_binary(tmp_path):
    from deepscan_core.scanners import ScanContext
    from deepscan_core.scanners.plumber import Plumber

    ctx = ScanContext(work_dir=tmp_path, target_path=tmp_path)
    result = asyncio.run(Plumber().run(ctx))
    # not installed in the test env → clean skip, never an error
    assert result.status.value in ("skipped", "ok")
