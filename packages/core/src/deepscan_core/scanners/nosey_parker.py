"""``nosey_parker`` scanner - Nosey Parker secret detection (Praetorian).

Nosey Parker finds secrets and sensitive data with a large built-in regex rule
set and entropy analysis, scanning into an on-disk datastore. We run it in two
steps - ``scan`` into a scratch datastore, then ``report --format sarif`` - and
parse the SARIF into normalized ``Finding`` objects. Fully local; no external
API calls (no secret validation). Disable with ``NOSEY_PARKER=false``.
"""

from __future__ import annotations

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


class NoseyParker(Scanner):
    name = "nosey_parker"
    family = Family.SECRET
    mode = Mode.STATIC
    tool = "nosey_parker"
    description = "Secret detection via Nosey Parker (regex + entropy), local only"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("nosey_parker needs a directory target.")
        binary = self.binary()  # skips cleanly if not installed
        datastore = ctx.work_dir / "datastore.np"

        # No git-history switch needed: pointed at a directory, nosey_parker
        # scans the full history of any git checkout it finds by default
        # (``--git-history=full``), and just the files when there is no ``.git``.
        scan_cmd = [str(binary), "scan", "-d", str(datastore)]
        cfg = self.config_dir()  # operator config/nosey_parker/ custom rules
        if cfg is not None:
            scan_cmd += ["--ruleset", "default", "--rules-path", str(cfg)]
        scan_cmd += ["--", str(ctx.target_path)]
        code, _out, err = await self._run(scan_cmd)
        if not datastore.exists():
            raise ScannerSkipped(
                f"nosey_parker scan produced no datastore (exit {code}): {err.strip()[-200:]}"
            )
        code, stdout, err = await self._run(
            [str(binary), "report", "-d", str(datastore), "--format", "sarif"]
        )
        if not stdout.strip():
            raise ScannerSkipped(
                f"nosey_parker produced no SARIF (exit {code}): {err.strip()[-200:]}"
            )
        self.save_raw(ctx, "nosey_parker.sarif", stdout)
        return parse_sarif(stdout, tool=self.name, family=self.family)
