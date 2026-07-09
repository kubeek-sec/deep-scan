"""Catalog/registry wiring + parsing for the clamav and cisco-ai-skill-scanner
scanners. Deterministic and offline (no real tool download/run)."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from deepscan_core import install, registry
from deepscan_core.install.catalog import TOOLS, ToolKind
from deepscan_core.models import Family, Mode
from deepscan_core.scanners.base import ScanContext
from deepscan_core.scanners.cisco_ai_skill_scanner import CiscoAiSkillScanner
from deepscan_core.scanners.clamav import Clamav


def test_catalog_system_and_uv_kinds():
    clamav = TOOLS["clamav"]
    assert clamav.kind is ToolKind.SYSTEM
    assert clamav.executable == "clamscan" and clamav.system_package == "clamav"
    assert clamav.artifacts == {}  # SYSTEM tools have no pinned artifacts

    cisco = TOOLS["cisco-ai-skill-scanner"]
    assert cisco.kind is ToolKind.UV
    assert cisco.uv_package == "cisco-ai-skill-scanner"
    assert cisco.executable == "skill-scanner"
    assert cisco.version and cisco.version[0].isdigit()  # pinned PyPI version


def test_registry_wiring():
    names = {s["name"] for s in registry.describe()}
    assert {"clamav", "cisco-ai-skill-scanner"} <= names
    assert registry.get("clamav").family is Family.MALWARE
    assert registry.get("clamav").mode is Mode.STATIC
    assert registry.get("cisco-ai-skill-scanner").family is Family.SAST
    assert registry.get("cisco-ai-skill-scanner").mode is Mode.STATIC


def test_family_malware_exists():
    assert Family.MALWARE.value == "malware"
    assert Family("malware") is Family.MALWARE


def test_clamav_parses_found_lines():
    out = (
        "/x/evil.bin: Win.Test.EICAR_HDB-1 FOUND\n"
        "/x/clean.txt: OK\n"
        "/x/weird: name.py: Unix.Trojan.Generic FOUND\n"  # path containing ': '
        "----------- SCAN SUMMARY -----------\n"
    )
    findings = Clamav()._parse(out)
    assert len(findings) == 2
    first = findings[0]
    assert first.severity.value == "critical"
    assert first.rule == "Win.Test.EICAR_HDB-1"
    assert first.location == "/x/evil.bin"
    assert first.cwes == ["CWE-506"]
    # rpartition keeps the full path even when it contains ": "
    assert findings[1].location == "/x/weird: name.py"
    assert findings[1].rule == "Unix.Trojan.Generic"


def test_uv_run_command_prefers_path(monkeypatch):
    monkeypatch.setattr(install.shutil, "which", lambda *a, **k: "/usr/bin/skill-scanner")
    assert install.uv_run_command("cisco-ai-skill-scanner") == ["/usr/bin/skill-scanner"]


def test_uv_run_command_uvx_fallback(monkeypatch):
    monkeypatch.setattr(install.shutil, "which", lambda *a, **k: None)
    cmd = install.uv_run_command("cisco-ai-skill-scanner")
    version = TOOLS["cisco-ai-skill-scanner"].version
    assert cmd == ["uvx", "--from", f"cisco-ai-skill-scanner=={version}", "skill-scanner"]


def test_cisco_skips_when_not_installed(monkeypatch):
    import deepscan_core.scanners.cisco_ai_skill_scanner as mod

    monkeypatch.setattr(mod.install, "is_installed", lambda name: False)
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d) / "p"
        proj.mkdir()
        ctx = ScanContext(work_dir=Path(d), target_path=proj)
        result = asyncio.run(mod.CiscoAiSkillScanner().run(ctx))
    assert result.status.value == "skipped"
    assert "not installed" in (result.skip_reason or "")


def test_clamav_skips_when_not_installed(monkeypatch):
    import deepscan_core.scanners.base as base

    monkeypatch.setattr(base, "tool_path", lambda name: None)
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d) / "p"
        proj.mkdir()
        ctx = ScanContext(work_dir=Path(d), target_path=proj)
        result = asyncio.run(Clamav().run(ctx))
    assert result.status.value == "skipped"


def test_install_all_skips_system_and_uv(monkeypatch):
    # `install all` must not attempt SYSTEM (clamav) / UV (cisco) tools - they
    # have external prerequisites and are installed explicitly.
    attempted = []

    def fake_install(name, *, force=False):
        attempted.append(name)
        return install.status(name)

    monkeypatch.setattr(install, "install", fake_install)
    install.install_all()
    assert "clamav" not in attempted
    assert "cisco-ai-skill-scanner" not in attempted
    assert "trivy" in attempted  # a normal downloadable tool is still attempted
    # …but they ARE installed when named explicitly.
    attempted.clear()
    install.install_all(["clamav"])
    assert attempted == ["clamav"]


def test_checkov_catalog_and_registry():
    ck = TOOLS["checkov"]
    assert ck.kind is ToolKind.UV
    assert ck.uv_package == "checkov" and ck.executable == "checkov"
    assert ck.version and ck.version[0].isdigit()  # pinned PyPI version
    assert registry.get("checkov").family is Family.IAC
    assert registry.get("checkov").mode is Mode.STATIC


def test_checkov_skips_when_not_installed(monkeypatch):
    import deepscan_core.scanners.checkov as mod

    monkeypatch.setattr(mod.install, "is_installed", lambda name: False)
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d) / "p"
        proj.mkdir()
        ctx = ScanContext(work_dir=Path(d), target_path=proj)
        result = asyncio.run(mod.Checkov().run(ctx))
    assert result.status.value == "skipped"
    assert "not installed" in (result.skip_reason or "")
