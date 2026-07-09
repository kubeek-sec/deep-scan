"""Trivy-based scanners: SCA (dependency vulnerabilities), IaC misconfiguration
and license compliance - three scanners sharing one pinned binary."""

from __future__ import annotations

from pathlib import Path

from .. import config
from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


class _TrivyBase(Scanner):
    mode = Mode.STATIC
    tool = "trivy"
    trivy_scanners: str = ""
    # Whether this scanner can offload to a Trivy server (client/server mode).
    # Only vulnerability matching uses the central DB, so only SCA opts in;
    # misconfig/license analysis is local and stays client-side.
    supports_server: bool = False
    # Pass ``--offline-scan``: Trivy never reaches out to a package registry to
    # resolve dependencies (notably the Java analyzer fetching parent POMs from
    # Maven Central). A single dependency-heavy Maven scan can otherwise trigger
    # a 429 that blocks this IP for ~30 min, failing every subsequent scan. Full
    # Java coverage (versions that live only in un-cached remote parent POMs) is
    # restored out-of-band by the sandboxed dependency resolver, not by Trivy.
    offline_scan: bool = False

    def _build_cmd(self, binary: str, out: Path, target: Path) -> list[str]:
        cmd = [binary, "--quiet"]
        cfg = self.config_file("*.yaml", "*.yml")  # operator config/<name>/ trivy config
        if cfg is not None:
            cmd += ["--config", str(cfg)]
        cmd += ["fs"]
        if self.offline_scan:
            cmd += ["--offline-scan"]
        if self.supports_server:
            server = config.trivy_server()
            if server:
                # Client mode: the server owns the vuln DB; this client pulls none.
                cmd += ["--server", server]
        cmd += [
            "--scanners",
            self.trivy_scanners,
            "--format",
            "sarif",
            "--output",
            str(out),
            "--",
            str(target),
        ]
        return cmd

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("Static scanner needs a directory target.")
        out = ctx.work_dir / f"{self.name}.sarif"
        cmd = self._build_cmd(str(self.binary()), out, ctx.target_path)
        code, _stdout, stderr = await self._run(cmd)
        if not out.is_file():
            raise RuntimeError(f"trivy exited {code} without SARIF output: {stderr[-500:]}")
        text = out.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.sarif", text)
        return parse_sarif(text, tool=self.name, family=self.family)


class TrivySca(_TrivyBase):
    name = "trivy"
    family = Family.SCA
    trivy_scanners = "vuln"
    supports_server = True
    offline_scan = True  # never hammer Maven Central & co. (429 -> 30-min IP block)
    description = "Dependency vulnerabilities (npm, pip, gems, go.mod, ...)"


class TrivyMisconfig(_TrivyBase):
    name = "trivy-misconfig"
    family = Family.IAC
    trivy_scanners = "misconfig"
    description = "IaC misconfiguration (Terraform, Kubernetes, Dockerfile, Helm, ...)"


class TrivyLicense(_TrivyBase):
    name = "trivy-license"
    family = Family.LICENSE
    trivy_scanners = "license"
    description = "License compliance of declared dependencies"
