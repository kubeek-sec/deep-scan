"""Opengrep: pattern-based SAST (semgrep-compatible engine and rules)."""

from __future__ import annotations

import os

from .. import config
from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


class Opengrep(Scanner):
    name = "opengrep"
    family = Family.SAST
    mode = Mode.STATIC
    tool = "opengrep"
    description = "Pattern-based SAST and CI-pipeline rules (semgrep-compatible)"

    def _rules(self) -> str:
        """Rule source for ``--config``: an operator ``config/opengrep/`` dir wins,
        else ``DEEPSCAN_OPENGREP_RULES`` (default ``auto`` = the semgrep registry)."""
        cfg = self.config_dir()
        return str(cfg) if cfg else config.get("DEEPSCAN_OPENGREP_RULES", "auto")

    @staticmethod
    def _build_cmd(binary: str, target, out, rules: str) -> list[str]:
        return [
            binary, "scan", "--quiet", "--config", rules,
            "--sarif-output", str(out), str(target),
        ]

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("Static scanner needs a directory target.")
        out = ctx.work_dir / f"{self.name}.sarif"
        cmd = self._build_cmd(str(self.binary()), ctx.target_path, out, self._rules())
        # opengrep (a semgrep fork) creates a settings dir at $HOME/.opengrep on
        # startup; under a read-only rootfs (the hardened kruncher) that write
        # fails with EROFS. Point HOME at the per-scan scratch (writable, under
        # TMPDIR) just for this subprocess - the engine cache still resolves via
        # XDG_CACHE_HOME, and other tools keep the real $HOME (e.g. nuclei's
        # baked templates).
        env = {**os.environ, "HOME": str(ctx.work_dir)}
        code, _stdout, stderr = await self._run(cmd, env=env)
        if not out.is_file():
            raise RuntimeError(f"opengrep exited {code} without SARIF output: {stderr[-500:]}")
        text = out.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.sarif", text)
        return parse_sarif(text, tool=self.name, family=self.family)
