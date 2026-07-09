"""Trivy client/server mode: the SCA scanner offloads to a Trivy server when
configured, while misconfig/license stay local."""

from __future__ import annotations

from pathlib import Path

from deepscan_core.scanners.trivy import TrivyLicense, TrivyMisconfig, TrivySca

OUT = Path("/tmp/out.sarif")
TARGET = Path("/repo")


def test_sca_uses_server_when_set(monkeypatch):
    monkeypatch.setenv("DEEPSCAN_TRIVY_SERVER", "http://trivy-server:4954")
    cmd = TrivySca()._build_cmd("trivy", OUT, TARGET)
    assert "--server" in cmd
    assert cmd[cmd.index("--server") + 1] == "http://trivy-server:4954"
    # still a vuln fs scan into SARIF
    assert cmd[:3] == ["trivy", "--quiet", "fs"]
    assert "vuln" in cmd and str(TARGET) == cmd[-1]


def test_sca_local_when_unset(monkeypatch):
    monkeypatch.delenv("DEEPSCAN_TRIVY_SERVER", raising=False)
    monkeypatch.delenv("TRIVY_SERVER", raising=False)
    assert "--server" not in TrivySca()._build_cmd("trivy", OUT, TARGET)


def test_trivy_server_env_fallback(monkeypatch):
    monkeypatch.delenv("DEEPSCAN_TRIVY_SERVER", raising=False)
    monkeypatch.setenv("TRIVY_SERVER", "http://ts:4954")
    assert "--server" in TrivySca()._build_cmd("trivy", OUT, TARGET)


def test_misconfig_and_license_never_use_server(monkeypatch):
    monkeypatch.setenv("DEEPSCAN_TRIVY_SERVER", "http://trivy-server:4954")
    for scanner in (TrivyMisconfig(), TrivyLicense()):
        assert "--server" not in scanner._build_cmd("trivy", OUT, TARGET)
