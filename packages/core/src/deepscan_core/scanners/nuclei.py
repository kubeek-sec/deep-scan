"""Nuclei: template-based dynamic scanning of a running target URL.

Nuclei needs its **templates** (the separate ``nuclei-templates`` repo), which
are not part of the binary. They're expected to be present (baked into the image
or in the user's nuclei home). Knobs:

* ``DEEPSCAN_NUCLEI_UPDATE_TEMPLATES`` - refresh templates before each scan.
  **On by default** (best-effort: a blocked update falls back to baked/existing
  templates); set it falsey (``false``/``0``) to rely solely on baked templates.
* ``DEEPSCAN_NUCLEI_TEMPLATES`` - explicit templates directory (``-templates``).
* ``DEEPSCAN_NUCLEI_SEVERITY`` - severities to run (default ``medium,high,critical``).

If no templates are available, the scanner **skips cleanly** (with a hint)
rather than failing the scan.
"""

from __future__ import annotations

import json

from .. import config
from ..models import Family, Finding, Mode
from .base import ScanContext, Scanner, ScannerSkipped
from ..sarif import parse_sarif

_EMPTY_SARIF = json.dumps(
    {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "nuclei"}}, "results": []}],
    }
)

_FALSEY = {"false", "0", "no", "off", "disable", "disabled"}
_NO_TEMPLATES_HINTS = (
    "no templates provided",
    "no templates were found",
    "could not find any templates",
    "no such file or directory",  # nuclei-templates dir missing
)


class Nuclei(Scanner):
    name = "nuclei"
    family = Family.DAST
    mode = Mode.DYNAMIC
    tool = "nuclei"
    description = "Template-based dynamic vulnerability scanning"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.target_url:
            raise ScannerSkipped("Dynamic scanner needs a target URL.")
        binary = self.binary()

        # Refresh templates before each scan by default (newest rules / CVEs).
        # Best-effort: a blocked/slow update never fails the scan - it falls back
        # to whatever templates are present (e.g. those baked into the image).
        # Disable with DEEPSCAN_NUCLEI_UPDATE_TEMPLATES=false to rely on baked ones.
        if (config.get("DEEPSCAN_NUCLEI_UPDATE_TEMPLATES") or "").strip().lower() not in _FALSEY:
            try:
                await self._run([str(binary), "-update-templates", "-no-color"])
            except Exception:  # noqa: BLE001 - template refresh is best-effort
                pass

        out = ctx.work_dir / f"{self.name}.sarif"
        severities = config.get("DEEPSCAN_NUCLEI_SEVERITY", "medium,high,critical")
        cmd = [
            str(binary),
            "-target",
            ctx.target_url,
            "-severity",
            str(severities),
            "-sarif-export",
            str(out),
            "-no-color",
            "-duc",
        ]
        # Operator config/nuclei/ custom templates win, else DEEPSCAN_NUCLEI_TEMPLATES.
        cfg = self.config_dir()
        templates = str(cfg) if cfg else config.get("DEEPSCAN_NUCLEI_TEMPLATES")
        if templates and str(templates).strip():
            cmd += ["-templates", str(templates).strip()]

        code, stdout, stderr = await self._run(cmd)
        if not out.is_file():
            blob = f"{stderr}\n{stdout}".lower()
            if any(hint in blob for hint in _NO_TEMPLATES_HINTS):
                raise ScannerSkipped(
                    "nuclei has no templates installed - run 'nuclei -update-templates', "
                    "set DEEPSCAN_NUCLEI_UPDATE_TEMPLATES=1, point DEEPSCAN_NUCLEI_TEMPLATES "
                    "at a templates dir, or bake them into the image."
                )
            # nuclei writes no file when there are zero findings.
            if code == 0:
                text = _EMPTY_SARIF
            else:
                raise RuntimeError(f"nuclei exited {code}: {stderr[-500:]}")
        else:
            text = out.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.sarif", text)
        return parse_sarif(text, tool=self.name, family=self.family)
