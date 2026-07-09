"""ClamAV: virus / malware signatures across the working tree.

ClamAV is an OS package (``clamscan``), not a pinned single binary, so it is a
``SYSTEM`` tool: found on PATH and installed via the system package manager
(``deepscan tools install clamav``). It needs a virus database - ``freshclam``
is run after install; a missing DB makes the scan skip cleanly. Disable with
``CLAMAV=false``.
"""

from __future__ import annotations

from ..models import Family, Finding, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped

_FOUND_SUFFIX = " FOUND"


class Clamav(Scanner):
    name = "clamav"
    family = Family.MALWARE
    mode = Mode.STATIC
    tool = "clamav"
    description = "Virus/malware signatures across the working tree (ClamAV)"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("clamav needs a directory target.")
        binary = self.binary()  # clamscan path; skips cleanly if not installed
        cmd = [
            str(binary),
            "--recursive",
            "--infected",      # only report infected files
            "--no-summary",
            "--stdout",
            str(ctx.target_path),
        ]
        # Exit codes: 0 = clean, 1 = virus(es) found, 2 = error (often a missing DB).
        code, stdout, stderr = await self._run(cmd)
        if code >= 2:
            blob = f"{stderr}\n{stdout}".lower()
            if "database" in blob or "can't get file status" in blob:
                raise ScannerSkipped(
                    "ClamAV virus database missing - run 'freshclam' "
                    "(or 'deepscan tools install clamav')."
                )
            raise RuntimeError(f"clamscan exited {code}: {stderr.strip()[-300:]}")
        self.save_raw(ctx, f"{self.name}.txt", stdout)
        return self._parse(stdout)

    def _parse(self, stdout: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.endswith(_FOUND_SUFFIX):
                continue
            # Format: "<path>: <Signature> FOUND"
            path, sep, rest = line.rpartition(": ")
            if not sep:
                continue
            signature = rest[: -len(_FOUND_SUFFIX)].strip()
            findings.append(
                Finding(
                    tool=self.name,
                    family=self.family,
                    rule=signature or "malware",
                    severity=Severity.CRITICAL,
                    message=f"Malware signature {signature!r} detected by ClamAV",
                    location=path,
                    cwes=["CWE-506"],  # Embedded Malicious Code
                    extra={"signature": signature},
                )
            )
        return findings
