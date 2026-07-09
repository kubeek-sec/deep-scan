"""OWASP ZAP baseline scan, run in Docker.

Hardening: container runs as the host UID/GID, work dir is a private (0700)
scratch directory, host networking only so the container can reach targets on
localhost during local testing.
"""

from __future__ import annotations

import json
import os
import sys

from ..models import Family, Finding, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped

_RISK_MAP = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}


class Zap(Scanner):
    name = "zaproxy"
    family = Family.DAST
    mode = Mode.DYNAMIC
    tool = "zaproxy"
    description = "OWASP ZAP baseline scan (passive + spider) via Docker"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.target_url:
            raise ScannerSkipped("Dynamic scanner needs a target URL.")
        image = self.require_docker_image()
        work = ctx.work_dir / "zap"
        work.mkdir(mode=0o700, exist_ok=True)
        report_name = "zap-report.json"
        cmd = [
            "docker",
            "run",
            "--rm",
            "-u",
            f"{os.getuid()}:{os.getgid()}" if sys.platform != "win32" else "1000:1000",
            "-v",
            f"{work}:/zap/wrk:rw",
            "--network",
            "host",
            image,
            "zap-baseline.py",
            "-t",
            ctx.target_url,
            "-J",
            report_name,
            "-I",
        ]
        code, _stdout, stderr = await self._run(cmd)
        report_path = work / report_name
        if not report_path.is_file():
            raise RuntimeError(f"zap exited {code} without report: {stderr[-500:]}")
        text = report_path.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.json", text)
        return self._parse(text)

    def _parse(self, text: str) -> list[Finding]:
        doc = json.loads(text)
        findings: list[Finding] = []
        for site in doc.get("site") or []:
            site_name = site.get("@name") or "unknown"
            for alert in site.get("alerts") or []:
                severity = _RISK_MAP.get(str(alert.get("riskcode", "1")), Severity.LOW)
                instances = alert.get("instances") or []
                location = (instances[0].get("uri") if instances else None) or site_name
                cwe = alert.get("cweid")
                findings.append(
                    Finding(
                        tool=self.name,
                        family=self.family,
                        rule=f"zap-{alert.get('pluginid', 'unknown')}",
                        severity=severity,
                        message=alert.get("alert") or alert.get("name") or "ZAP alert",
                        location=location,
                        cwes=[f"CWE-{cwe}"] if cwe and str(cwe) not in ("-1", "0") else [],
                        extra={"instances": len(instances)},
                    )
                )
        return findings
