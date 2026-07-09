"""OSV-Scanner: dependency vulnerabilities against the OSV database."""

from __future__ import annotations

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


class OsvScanner(Scanner):
    name = "osv-scanner"
    family = Family.SCA
    mode = Mode.STATIC
    tool = "osv-scanner"
    description = "Dependency vulnerabilities from the OSV database"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("Static scanner needs a directory target.")
        out = ctx.work_dir / f"{self.name}.sarif"
        cmd = [
            str(self.binary()),
            "scan",
            "source",
            "--recursive",
            "--format",
            "sarif",
            "--output",
            str(out),
            str(ctx.target_path),
        ]
        # osv-scanner exits 1 when vulnerabilities are found - not an error.
        code, _stdout, stderr = await self._run(cmd)
        if not out.is_file():
            if "no package sources found" in stderr.lower():
                raise ScannerSkipped("No dependency manifests found in target.")
            raise RuntimeError(f"osv-scanner exited {code} without output: {stderr[-500:]}")
        text = out.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.sarif", text)
        return parse_sarif(text, tool=self.name, family=self.family)
