"""``titus`` scanner - Titus secret detection (Praetorian).

Titus scans a project for secrets into an on-disk datastore, then reports them.
We run ``scan`` into a scratch datastore, then ``report --format sarif`` (SARIF
on stdout), and parse it into normalized ``Finding`` objects. On a git checkout
we pass ``--git`` so it enumerates the whole commit history (secrets committed
then removed are still caught); otherwise it scans the working tree. No secret
validation / dynamic scoring is requested, so the scan stays fully local and
never contacts external APIs. Disable with ``TITUS=false``.
"""

from __future__ import annotations

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped, is_git_repo


class Titus(Scanner):
    name = "titus"
    family = Family.SECRET
    mode = Mode.STATIC
    tool = "titus"
    description = "Secret detection via Titus (local, no validation)"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("titus needs a directory target.")
        binary = self.binary()  # skips cleanly if not installed
        datastore = ctx.work_dir / "titus.ds"

        scan_cmd = [str(binary), "scan", "-q", "--output", str(datastore)]
        if is_git_repo(ctx.target_path):  # enumerate git history, not just the tree
            scan_cmd.append("--git")
        cfg = self.config_dir()  # operator config/titus/ custom rules file/dir
        if cfg is not None:
            scan_cmd += ["--rules", str(cfg)]
        scan_cmd += ["--", str(ctx.target_path)]
        code, _out, err = await self._run(scan_cmd)
        if not datastore.exists():
            raise ScannerSkipped(
                f"titus scan produced no datastore (exit {code}): {err.strip()[-200:]}"
            )
        code, stdout, err = await self._run(
            [str(binary), "report", "--datastore", str(datastore), "--format", "sarif"]
        )
        if not stdout.strip():
            raise ScannerSkipped(
                f"titus produced no SARIF (exit {code}): {err.strip()[-200:]}"
            )
        self.save_raw(ctx, "titus.sarif", stdout)
        return parse_sarif(stdout, tool=self.name, family=self.family)
