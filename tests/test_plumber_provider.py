"""Provider detection + skip behaviour for the plumber scanner.

Plumber decides GitHub vs GitLab from on-disk markers (not the git remote), so a
scan still runs on a copy-pasted repo (no ``.git``) or one with no remote. These
tests exercise that logic without downloading/running the real binary: detection
is a pure function, and the skip paths are reached by faking an installed binary.
"""

from __future__ import annotations

import asyncio

import pytest

from deepscan_core.scanners import ScanContext
from deepscan_core.scanners.plumber import Plumber, _detect_provider


def _write(path, text="x\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_detect_github_from_workflows(tmp_path):
    _write(tmp_path / ".github" / "workflows" / "ci.yml", "on: [push]\n")
    assert _detect_provider(tmp_path) == "github"


def test_detect_gitlab_from_root_yaml(tmp_path):
    for name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        d = tmp_path / name.strip(".")
        d.mkdir()
        _write(d / name, "build: {}\n")
        assert _detect_provider(d) == "gitlab"


def test_detect_none_without_ci_config(tmp_path):
    _write(tmp_path / "README.md")
    _write(tmp_path / ".github" / "ISSUE_TEMPLATE.md")  # .github but no workflows
    assert _detect_provider(tmp_path) is None


def test_skips_when_no_ci_config(tmp_path, monkeypatch):
    # Fake an installed binary so we reach the provider check, then expect a skip.
    monkeypatch.setattr(Plumber, "binary", lambda self: "/bin/true")
    _write(tmp_path / "README.md")
    result = asyncio.run(Plumber().run(ScanContext(work_dir=tmp_path, target_path=tmp_path)))
    assert result.status.value == "skipped" and "CI/CD config" in result.skip_reason


def test_skips_gitlab_without_remote(tmp_path, monkeypatch):
    monkeypatch.setattr(Plumber, "binary", lambda self: "/bin/true")
    _write(tmp_path / ".gitlab-ci.yml", "build: {}\n")  # no .git -> no remote
    result = asyncio.run(Plumber().run(ScanContext(work_dir=tmp_path, target_path=tmp_path)))
    assert result.status.value == "skipped" and "GITLAB_TOKEN" in result.skip_reason
