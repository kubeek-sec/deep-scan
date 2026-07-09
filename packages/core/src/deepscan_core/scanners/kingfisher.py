"""``kingfisher`` scanner - Kingfisher secret detection (MongoDB).

Kingfisher scans for secrets and emits SARIF on stdout in a single step
(``scan --format sarif --no-validate``). ``--no-validate`` keeps it fully local
(no calls out to validate candidate credentials). Output is parsed into
normalized ``Finding`` objects. Disable with ``KINGFISHER=false``.
"""

from __future__ import annotations

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


class Kingfisher(Scanner):
    name = "kingfisher"
    family = Family.SECRET
    mode = Mode.STATIC
    tool = "kingfisher"
    description = "Secret detection via Kingfisher (MongoDB), local only (no validation)"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("kingfisher needs a directory target.")
        binary = self.binary()  # skips cleanly if not installed
        # No git-history switch needed: pointed at a directory, kingfisher scans
        # the full git history of a checkout by default (``--git-history=full``)
        # and just the files when there is no ``.git``.
        cmd = [str(binary), "scan", "--format", "sarif", "--no-validate"]
        cfg = self.config_dir()  # operator config/kingfisher/ custom rules
        if cfg is not None:
            cmd += ["--rules-path", str(cfg)]
        cmd += ["--", str(ctx.target_path)]
        code, stdout, err = await self._run(cmd)
        if not stdout.strip():
            raise ScannerSkipped(
                f"kingfisher produced no SARIF (exit {code}): {err.strip()[-200:]}"
            )
        self.save_raw(ctx, "kingfisher.sarif", stdout)
        return parse_sarif(stdout, tool=self.name, family=self.family)
