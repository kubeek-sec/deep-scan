"""``checkov`` scanner - IaC / configuration misconfiguration (Bridgecrew Checkov).

Checkov audits Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM,
Serverless, GitHub Actions, etc. for misconfigurations. It's a Python tool
installed/run via uv (``deepscan tools install checkov`` → ``uv tool install``);
its SARIF output flows through the shared parser like every other scanner.
Disable with ``CHECKOV=false``.
"""

from __future__ import annotations

import os

from .. import install
from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


class Checkov(Scanner):
    name = "checkov"
    family = Family.IAC
    mode = Mode.STATIC
    tool = "checkov"
    description = "IaC / config misconfiguration (Terraform, K8s, Helm, Dockerfile, CloudFormation…) via Checkov"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("checkov needs a directory target.")
        if not install.is_installed(self.tool):
            raise ScannerSkipped(
                "checkov is not installed. Run: deepscan tools install checkov"
            )
        out_dir = ctx.work_dir / "checkov-out"
        out_dir.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "CHECKOV_DISABLE_TELEMETRY": "true"}
        cmd = install.uv_run_command(self.tool) + [
            "--directory", str(ctx.target_path),
            "--output", "sarif",
            "--output-file-path", str(out_dir),
            "--soft-fail",          # found checks must not set a non-zero exit
            "--compact",
        ]
        # Operator config/checkov/: custom checks dir + an optional config file.
        cfg = self.config_dir()
        if cfg is not None:
            cmd += ["--external-checks-dir", str(cfg)]
            config_file = self.config_file("*.yaml", "*.yml")
            if config_file is not None:
                cmd += ["--config-file", str(config_file)]
        code, stdout, stderr = await self._run(cmd, env=env)

        # checkov writes results_sarif.sarif (name varies by version) into the dir.
        sarif_files = sorted(out_dir.glob("*.sarif"))
        if sarif_files:
            text = sarif_files[0].read_text(encoding="utf-8", errors="replace")
        elif stdout.strip().startswith("{"):
            text = stdout
        elif code == 0:
            raise ScannerSkipped("checkov found no scannable IaC/config files in target.")
        else:
            raise RuntimeError(f"checkov exited {code}: {(stderr or stdout).strip()[-300:]}")

        self.save_raw(ctx, "checkov.sarif", text)
        return parse_sarif(text, tool=self.name, family=self.family)
