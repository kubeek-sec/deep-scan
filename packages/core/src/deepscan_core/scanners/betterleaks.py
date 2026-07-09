"""``betterleaks`` scanner - Betterleaks secret detection (Gitleaks successor).

Betterleaks emits SARIF on stdout in a single step. On a git checkout it walks
the full commit history (``git``, so secrets committed then removed are still
caught); otherwise it scans the working tree (``dir``). Live credential
validation is opt-in and left off, so the scan stays fully local. Output is
parsed into normalized ``Finding`` objects. Disable with ``BETTERLEAKS=false``.
"""

from __future__ import annotations

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped, is_git_repo


class Betterleaks(Scanner):
    name = "betterleaks"
    family = Family.SECRET
    mode = Mode.STATIC
    tool = "betterleaks"
    description = "Secret detection via Betterleaks (Gitleaks successor), local only"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("betterleaks needs a directory target.")
        binary = self.binary()  # skips cleanly if not installed
        subcmd = "git" if is_git_repo(ctx.target_path) else "dir"
        cmd = [str(binary), subcmd, "--report-format", "sarif", "--report-path", "-",
               str(ctx.target_path)]
        toml = self.config_file("*.toml")  # operator config/betterleaks/*.toml
        if toml is not None:
            cmd += ["--config", str(toml)]
        code, stdout, err = await self._run(cmd)
        if not stdout.strip():
            raise ScannerSkipped(
                f"betterleaks produced no SARIF (exit {code}): {err.strip()[-200:]}"
            )
        self.save_raw(ctx, "betterleaks.sarif", stdout)
        return parse_sarif(stdout, tool=self.name, family=self.family)
