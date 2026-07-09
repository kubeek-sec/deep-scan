"""Tests for the directory connector, including wrapping the guinea-pig project."""

from __future__ import annotations

from pathlib import Path

import pytest

from deepscan_input_connector_base import ConnectorConfigError, KIND_DIRECTORY, get

REPO_ROOT = Path(__file__).resolve().parents[1]
GUINEA_PIG = REPO_ROOT / "guinea-pig"


@pytest.fixture
def directory():
    return get("directory")


def test_subdirs_layout(directory, tmp_path):
    (tmp_path / "svc-a").mkdir()
    (tmp_path / "svc-b").mkdir()
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "loose.txt").write_text("x")  # files are not sources
    cfg = {"base_path": str(tmp_path), "layout": "subdirs"}
    names = sorted(s.name for s in directory.discover(cfg))
    assert names == ["svc-a", "svc-b"]  # hidden + loose file excluded


def test_name_regex_filter(directory, tmp_path):
    (tmp_path / "svc-a").mkdir()
    (tmp_path / "lib-b").mkdir()
    cfg = {"base_path": str(tmp_path), "name_regex": "^svc-"}
    names = [s.name for s in directory.discover(cfg)]
    assert names == ["svc-a"]


def test_single_layout_and_revision(directory, tmp_path):
    (tmp_path / "f.py").write_text("1")
    cfg = {"base_path": str(tmp_path), "layout": "single"}
    sources = list(directory.discover(cfg))
    assert len(sources) == 1 and sources[0].kind == KIND_DIRECTORY
    rev = directory.current_revision(sources[0], cfg)
    assert rev and len(rev) == 40


def test_materialize_in_place_does_not_copy(directory, tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    (src / "a").write_text("1")
    dest = tmp_path / "scratch"
    cfg = {"base_path": str(tmp_path), "layout": "subdirs"}
    source = next(iter(directory.discover(cfg)))
    out = directory.materialize(source, None, dest, cfg)
    assert Path(out) == src and not dest.exists()  # scanned in place


def test_materialize_snapshot_copies(directory, tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    (src / "a.py").write_text("1")
    (src / ".git").mkdir()
    (src / ".git" / "x").write_text("noise")
    dest = tmp_path / "scratch"
    cfg = {"base_path": str(tmp_path), "layout": "subdirs", "snapshot": True}
    source = next(iter(directory.discover(cfg)))
    out = directory.materialize(source, None, dest, cfg)
    assert Path(out) == dest and (dest / "a.py").exists()
    assert not (dest / ".git").exists()  # vcs dir excluded from snapshot


def test_invalid_config(directory):
    # discover() is a generator: force evaluation so validate_config runs.
    with pytest.raises(ConnectorConfigError):
        list(directory.discover({}))  # missing base_path
    with pytest.raises(ConnectorConfigError):
        list(directory.discover({"base_path": "/no/such/dir/xyz"}))
    # validate_config is also callable directly (eager).
    with pytest.raises(ConnectorConfigError):
        directory.validate_config({})


@pytest.mark.skipif(not GUINEA_PIG.is_dir(), reason="guinea-pig project not present")
def test_wraps_guinea_pig(directory):
    cfg = {"base_path": str(GUINEA_PIG), "layout": "single"}
    source = next(iter(directory.discover(cfg)))
    assert source.location == str(GUINEA_PIG.resolve())
    assert directory.current_revision(source, cfg)  # signature computes
