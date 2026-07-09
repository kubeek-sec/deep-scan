"""Scanner contract.

Every scanner follows the same shape so that adding a tool is mechanical:

1. Pin the tool in ``install/catalog.py`` (URL + SHA-256 per platform).
2. Subclass ``Scanner`` in ``scanners/<tool>.py``: set the class attributes
   and implement ``_execute()`` returning normalized ``Finding`` objects.
3. Register the instance in ``scanners/__init__.py``.

``Scanner.run()`` owns timing, availability checks and error containment -
a scanner never raises, it reports ``ok``, ``skipped`` or ``error``.
"""

from __future__ import annotations

import abc
import asyncio
import time
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from .. import config
from ..install import is_installed, tool_path
from ..install.catalog import TOOLS, ToolKind
from ..log import get_logger
from ..models import Family, Finding, Mode, ToolResult, ToolStatus

_log = get_logger("scanner")


def packaged_rules_dir(name: str) -> Path:
    """Default rule set shipped in the wheel: ``data/scanner_rules/<name>/``."""
    return Path(str(files("deepscan_core") / "data" / "scanner_rules" / name))


def is_git_repo(path: Path) -> bool:
    """True when ``path`` is a git checkout - a ``.git`` directory (a normal
    clone) or a ``.git`` file (a submodule / linked worktree). Secret scanners
    that can walk commit history switch to git-history mode when this holds and
    fall back to a plain directory scan otherwise."""
    dot_git = path / ".git"
    return dot_git.is_dir() or dot_git.is_file()


class ScannerSkipped(Exception):
    """Raised inside ``_execute`` when a prerequisite is missing or the
    scanner does not apply to the target. Treated as benign."""


@dataclass
class ScanOutput:
    """What ``_execute`` may return when a scanner emits structured output
    beyond findings (e.g. ai-analysis triage). Returning a plain ``list`` of
    findings is still supported and is equivalent to ``ScanOutput(findings)``."""

    findings: list["Finding"]
    payload: dict | None = None


@dataclass
class ScanContext:
    work_dir: Path  # scratch dir, removed after the scan
    raw_dir: Path | None = None  # if set, raw tool outputs are kept here
    target_path: Path | None = None  # static targets
    target_url: str | None = None  # dynamic targets
    # Findings produced by the first-phase (producer) scanners, made available
    # to second-phase consumer scanners (e.g. ``ai-analysis``) that triage and
    # prioritize across everything else found.
    prior_findings: list["Finding"] = field(default_factory=list)
    # Set by the runner's caller (the worker) when an operator cancels the job.
    # Long, CPU-bound scanners (e.g. ``analysis``) poll ``should_stop`` so they
    # can abort cooperatively instead of running to completion after a cancel.
    cancel_event: "threading.Event | None" = None

    @property
    def target(self) -> str:
        return str(self.target_path) if self.target_path else (self.target_url or "")

    def should_stop(self) -> bool:
        """True once the job has been cancelled (cooperative-abort signal)."""
        return self.cancel_event is not None and self.cancel_event.is_set()


class Scanner(abc.ABC):
    name: str
    family: Family
    mode: Mode
    description: str = ""
    tool: str | None = None  # key into install.catalog.TOOLS, if a binary is needed
    # Whether a full (unfiltered) scan includes this scanner. Off-by-default
    # scanners (e.g. the LLM scanner) still run when named explicitly or when
    # their env toggle is truthy.
    enabled_by_default: bool = True
    # A consumer scanner runs in a second phase, after the producer scanners,
    # and reads their findings from ``ctx.prior_findings`` (e.g. ``ai-analysis``
    # triages everything else). Producer scanners (the default) run first.
    consumes_findings: bool = False

    async def run(self, ctx: ScanContext) -> ToolResult:
        start = time.monotonic()
        _log.info("%s (%s): starting", self.name, self.family.value)
        try:
            out = await self._execute(ctx)
            findings = out.findings if isinstance(out, ScanOutput) else out
            payload = out.payload if isinstance(out, ScanOutput) else None
            elapsed = time.monotonic() - start
            _log.info(
                "%s: ok - %d finding(s) in %.1fs", self.name, len(findings), elapsed
            )
            return ToolResult(
                scanner=self.name,
                family=self.family,
                status=ToolStatus.OK,
                duration=elapsed,
                findings=findings,
                raw_output_path=self._raw_path(ctx),
                payload=payload,
            )
        except ScannerSkipped as exc:
            _log.info("%s: skipped - %s", self.name, exc)
            return ToolResult(
                scanner=self.name,
                family=self.family,
                status=ToolStatus.SKIPPED,
                duration=time.monotonic() - start,
                skip_reason=str(exc),
            )
        except asyncio.TimeoutError:
            _log.warning("%s: timed out after %ss", self.name, self.timeout)
            return ToolResult(
                scanner=self.name,
                family=self.family,
                status=ToolStatus.ERROR,
                duration=time.monotonic() - start,
                error=f"{self.name} timed out after {self.timeout}s",
            )
        except Exception as exc:  # noqa: BLE001 - a scanner must never crash the scan
            _log.error("%s: failed - %s", self.name, exc, exc_info=_log.isEnabledFor(10))
            return ToolResult(
                scanner=self.name,
                family=self.family,
                status=ToolStatus.ERROR,
                duration=time.monotonic() - start,
                error=f"{self.name} failed: {exc}",
            )

    @abc.abstractmethod
    async def _execute(self, ctx: ScanContext) -> "list[Finding] | ScanOutput": ...

    # ---- helpers for subclasses -------------------------------------------

    @property
    def timeout(self) -> int:
        return config.timeout_for(self.name)

    def config_dir(self) -> Path | None:
        """Operator-supplied rule/config dir for this scanner (``config/<name>/``),
        or ``None`` when absent/empty (use the tool's / packaged defaults)."""
        return config.scanner_config_dir(self.name)

    def config_file(self, *globs: str) -> Path | None:
        """First file (sorted) matching any of ``globs`` in this scanner's config
        dir, for tools that take a single rule/config file. ``None`` if none."""
        d = self.config_dir()
        if d is None:
            return None
        for pattern in globs:
            matches = sorted(d.glob(pattern))
            if matches:
                return matches[0]
        return None

    def binary(self) -> Path:
        """Installed binary path; skips the scanner when missing."""
        if not self.tool:
            raise ScannerSkipped(f"{self.name} has no managed binary.")
        path = tool_path(self.tool)
        if path is None:
            raise ScannerSkipped(
                f"{self.tool} is not installed. Run: deepscan tools install {self.tool}"
            )
        return path

    def require_docker_image(self) -> str:
        spec = TOOLS.get(self.tool or "")
        if spec is None or spec.kind != ToolKind.DOCKER:
            raise ScannerSkipped(f"{self.name} has no docker image configured.")
        if not is_installed(self.tool or ""):
            raise ScannerSkipped(
                f"Docker image {spec.docker_image} not present. "
                f"Run: deepscan tools install {self.tool}"
            )
        return spec.docker_image or ""

    async def _run(
        self,
        cmd: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> tuple[int, str, str]:
        """Run a subprocess without a shell, with a hard timeout."""
        _log.debug("%s: exec %s", self.name, " ".join(cmd))
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout or self.timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise
        return (
            process.returncode or 0,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )

    def save_raw(self, ctx: ScanContext, filename: str, text: str) -> None:
        if ctx.raw_dir is not None:
            ctx.raw_dir.mkdir(parents=True, exist_ok=True)
            (ctx.raw_dir / filename).write_text(text, encoding="utf-8")

    def _raw_path(self, ctx: ScanContext) -> str | None:
        if ctx.raw_dir is None:
            return None
        for candidate in ctx.raw_dir.glob(f"{self.name}.*"):
            return str(candidate)
        return None
