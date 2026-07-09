"""Tests for the CodeQL wrapper scanner (CLI not required - skip path + helpers)."""

from __future__ import annotations

import asyncio

from deepscan_core.scanners import ScanContext
from deepscan_core.scanners.codeql import CodeQL, _brief_error, detect_languages


def test_brief_error_extracts_node_cause():
    # Real CodeQL build log shape: noisy [ts][stream] prefixes, a Java stack
    # trace, and generic wrapper lines. _brief_error must surface the *cause*.
    log = (
        "[2026-06-19 17:01:45] [build-stdout] Extracting externs/lib/bdd.js\n"
        "[2026-06-19 17:01:45] [build-stderr] Could not start Node.js. "
        "It is required for TypeScript extraction.\n"
        "[2026-06-19 17:01:45] [build-stderr] Please install Node.js and "
        "ensure 'node' is on the PATH.\n"
        "[2026-06-19 17:01:45] [build-stderr] \tat com.semmle.ts.extractor."
        "TypeScriptParser.startNodeAndGetVersion(TypeScriptParser.java:256)\n"
        "[2026-06-19 17:01:45] [ERROR] Spawned process exited abnormally "
        "(code 1; tried to run: [.../autobuild.sh])\n"
        "A fatal error occurred: Exit status 1 from command: [.../autobuild.sh]\n"
    )
    reason = _brief_error(out="", err=log)
    assert "Node.js" in reason and "TypeScript extraction" in reason
    # the generic wrapper / stack-frame noise must be filtered out
    assert "fatal error occurred" not in reason.lower()
    assert "at com.semmle" not in reason


def test_brief_error_empty_is_blank():
    assert _brief_error("", "") == ""


def test_detect_languages(tmp_path):
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "b.ts").write_text("const x=1\n", encoding="utf-8")
    (tmp_path / "c.go").write_text("package main\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "d.js").write_text("1\n", encoding="utf-8")  # ignored
    langs = detect_languages(tmp_path)
    assert langs == {"python", "javascript", "go"}  # node_modules excluded


def test_create_cmd_build_modes(tmp_path):
    s = CodeQL()
    db = tmp_path / "db"
    # buildless language → plain create
    py = s._create_cmd("codeql", "python", tmp_path, db)
    assert py and "--build-mode=none" not in py and "--command" not in py
    # java → build-mode none
    java = s._create_cmd("codeql", "java", tmp_path, db)
    assert "--build-mode=none" in java
    # go without a build command → cannot create
    assert s._create_cmd("codeql", "go", tmp_path, db) is None


def test_codeql_skips_without_cli(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    monkeypatch.setenv("DEEPSCAN_CODEQL_BIN", "definitely-not-a-real-codeql-binary")
    ctx = ScanContext(work_dir=tmp_path, target_path=tmp_path)
    result = asyncio.run(CodeQL().run(ctx))
    assert result.status.value == "skipped" and "not found" in result.skip_reason


def test_codeql_skips_without_sources(tmp_path):
    (tmp_path / "README.txt").write_text("hi\n", encoding="utf-8")
    ctx = ScanContext(work_dir=tmp_path, target_path=tmp_path)
    # CLI may or may not exist; either way no supported sources → skipped
    result = asyncio.run(CodeQL().run(ctx))
    assert result.status.value == "skipped"
