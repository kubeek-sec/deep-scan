"""Per-scanner runtime rule/config (config/<scanner>/) + packaged defaults.

No database or external tools needed - exercises the resolution helpers, the
YARA/mcp-threats loaders and the pure command builders.
"""

from __future__ import annotations

import json

import pytest

from deepscan_core import config
from deepscan_core.scanners.gitleaks import Gitleaks
from deepscan_core.scanners.mcp_threats import _load_raw_patterns
from deepscan_core.scanners.opengrep import Opengrep
from deepscan_core.scanners.yara_scan import _yara_sources


@pytest.fixture()
def cfgdir(tmp_path, monkeypatch):
    d = tmp_path / "config"
    monkeypatch.setenv("DEEPSCAN_CONFIG_DIR", str(d))
    return d


def test_scanner_config_dir_none_until_non_empty(cfgdir):
    assert config.scanner_config_dir("gitleaks") is None        # absent
    (cfgdir / "gitleaks").mkdir(parents=True)
    assert config.scanner_config_dir("gitleaks") is None        # present but empty
    (cfgdir / "gitleaks" / "gitleaks.toml").write_text("x\n", encoding="utf-8")
    assert config.scanner_config_dir("gitleaks") == cfgdir / "gitleaks"


def test_config_file_picks_first_match(cfgdir):
    (cfgdir / "gitleaks").mkdir(parents=True)
    (cfgdir / "gitleaks" / "gitleaks.toml").write_text("x\n", encoding="utf-8")
    assert Gitleaks().config_file("*.toml") == cfgdir / "gitleaks" / "gitleaks.toml"
    assert Gitleaks().config_file("*.yaml") is None


def test_gitleaks_cmd_injects_config_only_when_present(cfgdir):
    g = Gitleaks()
    assert "--config" not in g._build_cmd("gitleaks", "/t", "/o.sarif", g.config_file("*.toml"))
    (cfgdir / "gitleaks").mkdir(parents=True)
    f = cfgdir / "gitleaks" / "g.toml"
    f.write_text("x\n", encoding="utf-8")
    cmd = g._build_cmd("gitleaks", "/t", "/o.sarif", g.config_file("*.toml"))
    assert "--config" in cmd and str(f) in cmd


def test_opengrep_rules_prefers_config_dir(cfgdir, monkeypatch):
    monkeypatch.setenv("DEEPSCAN_OPENGREP_RULES", "auto")
    assert Opengrep()._rules() == "auto"
    d = cfgdir / "opengrep"
    d.mkdir(parents=True)
    (d / "rules.yaml").write_text("rules: []\n", encoding="utf-8")
    assert Opengrep()._rules() == str(d)


def test_yara_sources_packaged_then_runtime_override(cfgdir):
    base = _yara_sources()
    assert base and "command_injection" in base          # packaged defaults present
    yd = cfgdir / "yara"
    yd.mkdir(parents=True)
    (yd / "custom.yara").write_text("rule c { condition: false }", encoding="utf-8")
    (yd / "command_injection.yara").write_text("rule ov { condition: false }", encoding="utf-8")
    merged = _yara_sources()
    assert "custom" in merged                             # new rule added
    assert merged["command_injection"] != base["command_injection"]   # same stem overridden


def test_mcp_threats_packaged_and_runtime_overlay(cfgdir):
    base = _load_raw_patterns()
    assert {"instruction-override", "tool-poisoning", "data-exfiltration"} <= set(base)
    md = cfgdir / "mcp-threats"
    md.mkdir(parents=True)
    (md / "patterns.json").write_text(
        json.dumps({"my-cat": {"severity": "low", "cwe": "CWE-1", "patterns": ["foo"]}}),
        encoding="utf-8",
    )
    merged = _load_raw_patterns()
    assert "my-cat" in merged and merged["my-cat"][0].value == "low"  # runtime category added
    assert "tool-poisoning" in merged                                 # packaged still present
