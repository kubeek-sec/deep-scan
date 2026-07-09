"""``analysis`` scanner - code-graph security analysis (no AI).

Builds the graphoofy code graph (a knowledge base + structural summary, written
as ``graph.json``/``graph.html`` when raw output is kept) and layers a
deterministic security analysis over it:

* precise Python AST taint (source → sink across functions, sanitizer-aware);
* multi-language tree-sitter detection of dangerous call-sites ("risk zones").

It emits the same normalized ``Finding`` objects as every other scanner, so the
results flow through dedup, the four report formats, the API/kruncher and the
ASPM dashboard unchanged - and feed the ``ai-analysis`` triage scanner.
"""

from __future__ import annotations

import asyncio
import time

from .. import config
from ..analysis import AnalysisAborted, analyze_target
from ..models import Family, Finding, Mode
from .base import ScanContext, Scanner, ScannerSkipped


class Analysis(Scanner):
    name = "analysis"
    family = Family.ANALYSIS
    mode = Mode.STATIC
    tool = None  # pure-Python engine + graphoofy, no managed binary
    description = "Code-graph (graphoofy) + taint/sanitization security analysis"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("analysis scanner needs a directory target.")
        # The engine parses with ast/tree-sitter (CPU-bound, synchronous); run
        # it off the event loop so concurrent scanners are not blocked.
        #
        # Two stop conditions guard this otherwise-unbounded pass:
        #  * a cooperative wall-clock *budget* checked inside the engine, so a
        #    pathological whole-program graph stops cleanly (the thread exits)
        #    instead of pegging a core forever; and
        #  * ``ctx.should_stop`` so an operator cancel aborts it within seconds.
        # ``asyncio.wait_for`` is only a hard backstop - it abandons the awaited
        # thread but cannot kill it, so the cooperative budget must fire first.
        budget = config.analysis_budget_seconds()
        deadline = time.monotonic() + budget if budget else None
        hard_timeout = max(self.timeout, budget + 30) if budget else self.timeout
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    analyze_target,
                    ctx.target_path,
                    ctx.work_dir,
                    ctx.raw_dir,
                    deadline=deadline,
                    should_stop=ctx.should_stop,
                ),
                timeout=hard_timeout,
            )
        except AnalysisAborted as exc:
            if exc.reason == "cancelled":
                # The job was cancelled mid-run; let the worker finalize it as
                # cancelled rather than recording a spurious scanner error.
                raise ScannerSkipped("analysis cancelled by operator") from exc
            raise RuntimeError(
                f"analysis exceeded its {budget}s taint budget "
                f"(graph too large/dense - raise DEEPSCAN_ANALYSIS_BUDGET to allow more)"
            ) from exc
        if ctx.raw_dir is not None and result.graph_summary:
            import json

            self.save_raw(ctx, "analysis.json", json.dumps(
                {"graph_summary": result.graph_summary,
                 "artifacts": result.artifacts,
                 "findings": [f.to_dict() for f in result.findings]},
                indent=2,
            ))
        return result.findings
