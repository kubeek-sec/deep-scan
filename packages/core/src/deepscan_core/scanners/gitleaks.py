"""Gitleaks: hardcoded secrets. Scans the full commit history when the target
is a git checkout (``gitleaks git``), else the working tree (``gitleaks dir``)."""

from __future__ import annotations

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped, is_git_repo


class Gitleaks(Scanner):
    name = "gitleaks"
    family = Family.SECRET
    mode = Mode.STATIC
    tool = "gitleaks"
    description = "Hardcoded secrets, API keys and tokens"

    @staticmethod
    def _build_cmd(binary: str, target, out, config_file=None, git_history=False) -> list[str]:
        # ``git`` walks the whole commit history (secrets committed then removed
        # are still there); ``dir`` only sees the current working tree.
        cmd = [
            binary, "git" if git_history else "dir", str(target),
            "--report-format", "sarif", "--report-path", str(out),
            "--exit-code", "0", "--no-banner",
        ]
        if config_file is not None:  # operator config/gitleaks/*.toml
            cmd += ["--config", str(config_file)]
        return cmd

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("Static scanner needs a directory target.")
        out = ctx.work_dir / f"{self.name}.sarif"
        cmd = self._build_cmd(
            str(self.binary()), ctx.target_path, out, self.config_file("*.toml"),
            git_history=is_git_repo(ctx.target_path),
        )
        code, _stdout, stderr = await self._run(cmd)
        if not out.is_file():
            raise RuntimeError(f"gitleaks exited {code} without report: {stderr[-500:]}")
        text = out.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.sarif", text)
        findings = parse_sarif(text, tool=self.name, family=self.family)
        for finding in findings:
            finding.cwes = finding.cwes or ["CWE-798"]
        return findings
