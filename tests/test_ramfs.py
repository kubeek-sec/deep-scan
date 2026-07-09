"""RAM-backed scan staging (``deepscan_jobs.ramfs``). No database needed."""

from __future__ import annotations

from pathlib import Path

from deepscan_jobs import ramfs


def _project(tmp_path: Path) -> Path:
    d = tmp_path / "proj"
    d.mkdir()
    (d / "app.py").write_text("x = 1\n", encoding="utf-8")
    (d / ".git").mkdir()
    (d / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    return d


def test_stages_into_configured_ram_dir_and_cleans_up(tmp_path, monkeypatch):
    ram = tmp_path / "ram"
    ram.mkdir()
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS", "true")
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS_DIR", str(ram))
    proj = _project(tmp_path)

    with ramfs.staged_for_scan(proj) as scan_path:
        copy = Path(scan_path)
        assert copy != proj                       # a copy, not the original
        assert str(copy).startswith(str(ram))     # under the RAM root
        assert (copy / "app.py").is_file()
        # Full fidelity: nothing excluded - .git history must be copied too so
        # scanners that walk it (secret history, etc.) see everything.
        assert (copy / ".git" / "config").is_file()

    assert not copy.exists()                       # copy removed on exit
    assert (proj / "app.py").is_file()             # original untouched
    assert (proj / ".git").exists()


def test_copy_is_removed_even_when_scan_raises(tmp_path, monkeypatch):
    ram = tmp_path / "ram"
    ram.mkdir()
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS", "true")
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS_DIR", str(ram))
    proj = _project(tmp_path)

    captured: dict[str, Path] = {}
    try:
        with ramfs.staged_for_scan(proj) as scan_path:
            captured["copy"] = Path(scan_path)
            raise RuntimeError("scan blew up")
    except RuntimeError:
        pass
    assert not captured["copy"].exists()


def test_disabled_scans_in_place(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS", "false")
    proj = _project(tmp_path)
    with ramfs.staged_for_scan(proj) as scan_path:
        assert scan_path == str(proj)


def test_unavailable_ram_dir_falls_back_in_place(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS", "true")
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS_DIR", str(tmp_path / "nope"))
    proj = _project(tmp_path)
    with ramfs.staged_for_scan(proj) as scan_path:
        assert scan_path == str(proj)


def test_non_directory_target_passthrough(monkeypatch):
    monkeypatch.setenv("DEEPSCAN_SCAN_RAMFS", "true")
    # A dynamic URL target is not a directory - yielded unchanged, never raises.
    with ramfs.staged_for_scan("https://example.test") as scan_path:
        assert scan_path == "https://example.test"
