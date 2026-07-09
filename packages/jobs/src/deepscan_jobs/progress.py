"""Live per-step progress tracking for a running scan job.

A :class:`JobProgress` builds the ordered list of *steps* a job goes through -
the lifecycle phases (acquire the source, write the report) plus one step per
scanner - and tracks each step's state as it runs. The worker persists snapshots
to ``scan_jobs.steps`` (JSONB) so a dashboard can show "step N / total" and a
log of what completed, what is running and what is left.

The tracker is updated from the asyncio event loop (the runner's ``on_progress``
hook and the worker's phase calls), so its in-memory mutations are race-free; a
separate pump persists snapshots on a timer (see ``worker._progress_pump``).
"""

from __future__ import annotations

import datetime as dt
from typing import Any

# Step lifecycle states. "ok" results from the scanner map to "done".
PENDING, RUNNING, DONE, SKIPPED, ERROR = "pending", "running", "done", "skipped", "error"
_TERMINAL = (DONE, SKIPPED, ERROR)
_SCANNER_STATUS = {"ok": DONE, "skipped": SKIPPED, "error": ERROR}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class JobProgress:
    """Ordered, mutable set of job steps with a JSON-serializable snapshot."""

    def __init__(self) -> None:
        self._steps: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        self._dirty = True

    # -- lifecycle phases (owned by the worker) ----------------------------- #

    def add_phase(self, name: str, label: str) -> None:
        if name not in self._steps:
            self._steps[name] = {"name": name, "label": label, "kind": "phase", "status": PENDING}
            self._order.append(name)
            self._dirty = True

    def start(self, name: str) -> None:
        step = self._steps.get(name)
        if step is not None:
            step["status"] = RUNNING
            step["started_at"] = _now()
            self._dirty = True

    def finish(
        self,
        name: str,
        *,
        status: str = DONE,
        duration: float | None = None,
        findings: int | None = None,
        detail: str | None = None,
    ) -> None:
        step = self._steps.get(name)
        if step is None:
            return
        step["status"] = status
        step["finished_at"] = _now()
        if duration is not None:
            step["duration"] = round(duration, 2)
        if findings is not None:
            step["findings"] = findings
        if detail:
            step["detail"] = detail[:300]
        self._dirty = True

    def fail_running(self, detail: str | None = None) -> None:
        """Mark any in-flight step as errored - call when the job blows up so the
        live view doesn't leave a step spinning forever."""
        for name in self._order:
            step = self._steps[name]
            if step["status"] == RUNNING:
                step["status"] = ERROR
                step["finished_at"] = _now()
                if detail:
                    step["detail"] = detail[:300]
                self._dirty = True

    # -- runner hook (one step per scanner) --------------------------------- #

    def on_scan_event(self, kind: str, data: dict[str, Any]) -> None:
        """Adapt :func:`deepscan_core.run_scan`'s ``on_progress`` events."""
        if kind == "plan":
            # Insert scanner steps ahead of the first post-scan phase (report).
            at = self._order.index("report") if "report" in self._order else len(self._order)
            for sc in data.get("scanners", []):
                name = sc["name"]
                if name in self._steps:
                    continue
                self._steps[name] = {
                    "name": name, "label": name, "kind": "scanner",
                    "family": sc.get("family"), "status": PENDING,
                }
                self._order.insert(at, name)
                at += 1
            self._dirty = True
        elif kind == "start":
            self.start(data["name"])
        elif kind == "finish":
            self.finish(
                data["name"],
                status=_SCANNER_STATUS.get(data.get("status"), DONE),
                duration=data.get("duration"),
                findings=data.get("findings"),
                detail=data.get("detail"),
            )

    # -- snapshot / persistence helpers ------------------------------------- #

    def take_dirty(self) -> bool:
        """Return whether there are unpersisted changes, clearing the flag."""
        dirty, self._dirty = self._dirty, False
        return dirty

    def snapshot(self) -> dict[str, Any]:
        steps = [self._steps[n] for n in self._order]
        done = sum(1 for s in steps if s["status"] in _TERMINAL)
        return {"total": len(steps), "done": done, "steps": steps}

    def completion(self) -> int:
        steps = self._order
        if not steps:
            return 0
        done = sum(1 for n in steps if self._steps[n]["status"] in _TERMINAL)
        return round(done / len(steps) * 100)

    def stage(self) -> str | None:
        """A short label of what's happening now (the running step(s))."""
        running = [n for n in self._order if self._steps[n]["status"] == RUNNING]
        if not running:
            return None
        if len(running) == 1:
            return self._steps[running[0]].get("label") or running[0]
        return f"{len(running)} scanners running"
