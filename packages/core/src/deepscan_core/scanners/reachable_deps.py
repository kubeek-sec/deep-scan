"""``reachable-deps`` scanner - correlate SCA findings with the code graph.

A *consumer* scanner: after the producer scanners run, it reads their SCA
findings (trivy / osv-scanner) and, using the graphoofy import graph, reports for
each whether the vulnerable dependency is actually imported/used by the scanned
code and reachable from an entry point - turning "CVE present" into "CVE
exploitable / likely-unused". Deterministic, no AI, no external binary.
"""

from __future__ import annotations

import asyncio
import json

from ..analysis import dep_usage
from ..models import Family, Finding, Mode
from .base import ScanContext, Scanner, ScannerSkipped


class ReachableDeps(Scanner):
    name = "reachable-deps"
    family = Family.ANALYSIS
    mode = Mode.STATIC
    tool = None
    consumes_findings = True
    description = "Correlate SCA dependency CVEs with actual imports/usage + reachability"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("reachable-deps needs a directory target.")
        sca = [f for f in ctx.prior_findings if f.family is Family.SCA]
        if not sca:
            raise ScannerSkipped("no SCA findings to correlate.")
        findings = await asyncio.to_thread(
            dep_usage.analyze, ctx.target_path, ctx.work_dir, sca
        )
        if ctx.raw_dir is not None:
            self.save_raw(ctx, "reachable-deps.json", json.dumps(
                [f.to_dict() for f in findings], indent=2))
        return findings
