"""Scanned-tree identity (``deepscan_core.fingerprint``). No database needed."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from deepscan_core import fingerprint


def test_fingerprint_is_content_stable_across_copies(tmp_path):
    a = tmp_path / "a"
    (a / "sub").mkdir(parents=True)
    (a / "x.py").write_text("print(1)\n", encoding="utf-8")
    (a / "sub" / "y.txt").write_text("hello\n", encoding="utf-8")
    b = tmp_path / "b"
    shutil.copytree(a, b)

    fa = fingerprint.fingerprint_tree(a)
    assert fa and fa.startswith("sha512:")
    # Same content at a different location (e.g. a clone or the RAM copy) → same
    # digest. Independent of mtime/path, so it is a stable content identity.
    assert fa == fingerprint.fingerprint_tree(b)


def test_fingerprint_changes_with_content(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    (a / "x.py").write_text("print(1)\n", encoding="utf-8")
    before = fingerprint.fingerprint_tree(a)
    (a / "x.py").write_text("print(2)\n", encoding="utf-8")
    assert fingerprint.fingerprint_tree(a) != before


def test_fingerprint_includes_everything(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    (a / "x.py").write_text("print(1)\n", encoding="utf-8")
    clean = fingerprint.fingerprint_tree(a)

    # Nothing is excluded - .git history, vendored deps and build artifacts are
    # all part of what was received/scanned, so each changes the fingerprint.
    (a / ".git").mkdir()
    (a / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    with_git = fingerprint.fingerprint_tree(a)
    assert with_git != clean

    (a / "node_modules").mkdir()
    (a / "node_modules" / "dep.js").write_text("//\n", encoding="utf-8")
    (a / "x.pyc").write_bytes(b"\x00\x01")
    assert fingerprint.fingerprint_tree(a) != with_git


@pytest.mark.skipif(
    not all(shutil.which(t) for t in ("find", "sort", "xargs", "sha512sum")),
    reason="GNU coreutils (find/sort/xargs/sha512sum) not available",
)
def test_fingerprint_matches_documented_shell_command(tmp_path):
    d = tmp_path / "proj"
    (d / "sub").mkdir(parents=True)
    (d / ".git").mkdir()
    (d / "app.py").write_text("print(1)\n", encoding="utf-8")
    (d / "sub" / "y.txt").write_text("hello\n", encoding="utf-8")
    (d / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (d / "with space.txt").write_text("data\n", encoding="utf-8")

    got = fingerprint.fingerprint_tree(d)
    # The exact command documented for hand-verification must reproduce it.
    proc = subprocess.run(
        fingerprint.VERIFY_COMMAND,
        cwd=d, shell=True, capture_output=True, text=True, check=True,
    )
    assert got == f"sha512:{proc.stdout.split()[0]}"


def test_fingerprint_none_for_non_directory(tmp_path):
    assert fingerprint.fingerprint_tree(tmp_path / "missing") is None
    assert fingerprint.fingerprint_tree("https://example.test") is None


def test_git_commit_none_without_git(tmp_path):
    a = tmp_path / "plain"
    a.mkdir()
    (a / "x.py").write_text("x\n", encoding="utf-8")
    assert fingerprint.git_commit(a) is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_commit_reads_head(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.py").write_text("x\n", encoding="utf-8")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}

    def git(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True,
                       capture_output=True, env=env)

    git("init", "-q")
    git("config", "user.email", "t@example.test")
    git("config", "user.name", "Test")
    git("add", ".")
    git("commit", "-q", "-m", "init")

    sha = fingerprint.git_commit(repo)
    assert sha and len(sha) == 40 and all(c in "0123456789abcdef" for c in sha)
