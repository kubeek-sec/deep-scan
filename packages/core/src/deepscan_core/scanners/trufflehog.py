"""TruffleHog: secrets via regex + entropy. Native JSON-lines output is
normalized directly; raw secret values are never copied into findings.

On a git checkout it scans the whole commit history (``git file://<repo>``, so
secrets committed then removed are still caught); otherwise it scans the working
tree (``filesystem``). The two sources report their location under different
``SourceMetadata`` keys (``Git`` vs ``Filesystem``), both handled below."""

from __future__ import annotations

import json

from ..models import Family, Finding, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped, is_git_repo


class Trufflehog(Scanner):
    name = "trufflehog"
    family = Family.SECRET
    mode = Mode.STATIC
    tool = "trufflehog"
    description = "Secrets via regex + entropy analysis (no remote verification)"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("Static scanner needs a directory target.")
        if is_git_repo(ctx.target_path):
            # The git source takes a URI; a local checkout needs the file:// scheme
            # and an absolute path.
            cmd = [str(self.binary()), "git", f"file://{ctx.target_path.resolve()}"]
        else:
            cmd = [str(self.binary()), "filesystem", str(ctx.target_path)]
        cmd += ["--json", "--no-update", "--no-verification"]
        cfg = self.config_file("*.yaml", "*.yml")  # operator config/trufflehog/ custom detectors
        if cfg is not None:
            cmd += ["--config", str(cfg)]
        _code, stdout, _stderr = await self._run(cmd)
        self.save_raw(ctx, f"{self.name}.jsonl", stdout)
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            detector = event.get("DetectorName")
            if not detector:
                continue
            data = (event.get("SourceMetadata") or {}).get("Data") or {}
            # ``filesystem`` reports under "Filesystem", ``git`` under "Git"
            # (which also carries the commit the secret was introduced in).
            meta = data.get("Git") or data.get("Filesystem") or {}
            file = meta.get("file") or "unknown"
            line_no = meta.get("line")
            commit = meta.get("commit")
            redacted = event.get("Redacted") or ""
            message = f"Potential {detector} secret"
            if redacted:
                message += f" (redacted: {redacted})"
            if commit:  # git-history hit: point the reviewer at the commit
                message += f" in commit {commit[:12]}"
            findings.append(
                Finding(
                    tool=self.name,
                    family=self.family,
                    rule=f"trufflehog-{detector.lower()}",
                    severity=Severity.CRITICAL if event.get("Verified") else Severity.HIGH,
                    message=message,
                    location=f"{file}:{line_no}" if line_no else file,
                    cwes=["CWE-798"],
                )
            )
        return findings
