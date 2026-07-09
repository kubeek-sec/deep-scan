"""MCP transport-aware target resolution + zip upload staging.

The target-resolution tests need no database. The upload round-trip test is
gated on a throwaway Postgres in DEEPSCAN_TEST_DB_DSN.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from deepscan_core import Mode
from deepscan_mcp import server


@pytest.fixture(autouse=True)
def _reset_transport():
    saved = server._TRANSPORT
    yield
    server._TRANSPORT = saved
    os.environ.pop("DEEPSCAN_MCP_ALLOW_LOCAL_PATHS", None)


def test_stdio_uses_local_path():
    server._TRANSPORT = "stdio"
    assert server._resolve_target(
        mode=Mode.STATIC, project_dir="/code", upload_id=None, target_url=None
    ) == ("path", "/code")


def test_http_path_blocked_by_default():
    server._TRANSPORT = "streamable-http"
    with pytest.raises(ValueError, match="disabled for the http transport"):
        server._resolve_target(
            mode=Mode.STATIC, project_dir="/code", upload_id=None, target_url=None
        )


def test_http_path_allowed_with_env():
    server._TRANSPORT = "streamable-http"
    os.environ["DEEPSCAN_MCP_ALLOW_LOCAL_PATHS"] = "1"
    assert server._resolve_target(
        mode=Mode.STATIC, project_dir="/code", upload_id=None, target_url=None
    ) == ("path", "/code")


def test_dynamic_requires_url():
    server._TRANSPORT = "stdio"
    with pytest.raises(ValueError, match="target URL is required"):
        server._resolve_target(
            mode=Mode.DYNAMIC, project_dir=None, upload_id=None, target_url=None
        )
    assert server._resolve_target(
        mode=Mode.DYNAMIC, project_dir=None, upload_id=None, target_url="http://x"
    ) == ("url", "http://x")


def test_static_without_target_errors():
    server._TRANSPORT = "streamable-http"
    with pytest.raises(ValueError, match="project_dir .* or an upload_id"):
        server._resolve_target(
            mode=Mode.STATIC, project_dir=None, upload_id=None, target_url=None
        )


def test_build_zip_skips_noise(tmp_path):
    from deepscan_mcp.client import build_zip
    import io
    import zipfile

    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("//\n", encoding="utf-8")

    names = zipfile.ZipFile(io.BytesIO(build_zip(tmp_path))).namelist()
    assert "keep.py" in names
    assert not any(n.startswith(".git/") or n.startswith("node_modules/") for n in names)


# --------------------------------------------------------------------------- #
# Upload staging (needs Postgres)
# --------------------------------------------------------------------------- #

TEST_DSN = os.environ.get("DEEPSCAN_TEST_DB_DSN")

if TEST_DSN:
    os.environ["DEEPSCAN_DB_DSN"] = TEST_DSN


@pytest.mark.skipif(not TEST_DSN, reason="DEEPSCAN_TEST_DB_DSN not set")
def test_stage_and_resolve_upload(tmp_path):
    os.environ["DEEPSCAN_DATA_DIR"] = str(tmp_path / "data")
    from deepscan_core.targets import extract_zip  # noqa: F401 (ensures dep present)
    from deepscan_jobs import db, uploads
    from deepscan_mcp.client import build_zip

    db.init_schema()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "main.py").write_text("print('hi')\n", encoding="utf-8")

    zip_path = tmp_path / "proj.zip"
    zip_path.write_bytes(build_zip(proj))
    row = uploads.stage_zip(str(zip_path), "proj.zip")
    upload_id = row["id"]

    staged = uploads.resolve_upload(upload_id)
    assert staged is not None
    assert (Path(staged) / "main.py").is_file()

    # Full row (used for report provenance - the human-facing upload filename).
    full = uploads.get_upload(upload_id)
    assert full and full["filename"] == "proj.zip" and full["path"] == staged

    # _resolve_target maps an upload_id to a staged 'zip' target.
    server._TRANSPORT = "streamable-http"
    ttype, target = server._resolve_target(
        mode=Mode.STATIC, project_dir=None, upload_id=upload_id, target_url=None
    )
    assert ttype == "zip"
    assert target == staged

    # An unknown upload_id is rejected with actionable guidance.
    with pytest.raises(ValueError, match="Unknown upload_id"):
        server._resolve_target(
            mode=Mode.STATIC, project_dir=None, upload_id="bogus", target_url=None
        )
    db.close_pool()
