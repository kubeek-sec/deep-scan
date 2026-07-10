"""Dependency resolver framework.

A *resolver* generates a missing lockfile for one package ecosystem **without
executing the scanned project's code** (``--ignore-scripts`` / lock-only / no
build), so Trivy SCA can then see the full transitive dependency tree fully
offline. Package managers are pointed at the Nexus pull-through mirror, so the
resolver needs no direct internet.

This is deliberately NOT a :class:`~deepscan_core.scanners.base.Scanner`: it
produces no findings, it mutates the (throwaway RAM copy of the) source tree by
writing a lockfile, and it runs once, before the scanners. It is a distinct
trust zone - the strong-isolation rollout runs it in its own gVisor sandbox with
no secrets and Nexus-only egress (see deploy/nexus/README.md).
"""

from __future__ import annotations

import abc
import shutil
import subprocess  # nosec B404 - we run pinned package managers, never shell strings
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..log import get_logger

_log = get_logger("resolve")


class ResolveStatus(str, Enum):
    GENERATED = "generated"  # a lockfile was produced
    PRESENT = "present"      # a lockfile was already there - nothing to do
    SKIPPED = "skipped"      # ecosystem absent, or its tool is not installed
    FAILED = "failed"        # the lock command ran but did not succeed


@dataclass
class ResolveResult:
    ecosystem: str
    status: ResolveStatus
    lockfile: str | None = None
    reason: str = ""
    duration: float = 0.0


class Resolver(abc.ABC):
    ecosystem: str
    tool: str                       # binary that must be on PATH to resolve
    manifests: tuple[str, ...]      # any present -> this ecosystem applies
    lockfiles: tuple[str, ...]      # any present -> already resolved, skip
    # Whether this resolver is guaranteed to run NO project/dependency code
    # (metadata-only). The rollout enables only these first; build-executing
    # ecosystems (maven/nuget/python-sdist) wait for the gVisor sandbox.
    no_exec: bool = True

    def applies(self, root: Path) -> bool:
        return any((root / m).is_file() for m in self.manifests)

    def already_locked(self, root: Path) -> Path | None:
        for lf in self.lockfiles:
            if (root / lf).is_file():
                return root / lf
        return None

    @abc.abstractmethod
    def command(self, root: Path) -> list[str]:
        """The lock-without-exec command to run (argv, never a shell string)."""

    def environment(self, base: dict[str, str], nexus_url: str | None,
                    work: Path) -> dict[str, str]:
        """Return the subprocess env, injecting the Nexus registry when set.
        ``work`` is a private scratch dir this resolver may write manager config
        into (never the scanned tree). Default: unchanged."""
        return base

    def produced(self, root: Path) -> Path | None:
        """The lockfile this resolver aims to produce (first of ``lockfiles``)."""
        return root / self.lockfiles[0] if self.lockfiles else None

    def resolve(self, root: Path, *, nexus_url: str | None, timeout: int,
                base_env: dict[str, str], work: Path) -> ResolveResult:
        start = time.monotonic()

        def done(status: ResolveStatus, **kw) -> ResolveResult:
            return ResolveResult(self.ecosystem, status,
                                 duration=time.monotonic() - start, **kw)

        if not self.applies(root):
            return done(ResolveStatus.SKIPPED, reason="no manifest")
        locked = self.already_locked(root)
        if locked is not None:
            return done(ResolveStatus.PRESENT, lockfile=locked.name,
                        reason="lockfile already present")
        if shutil.which(self.tool) is None:
            return done(ResolveStatus.SKIPPED, reason=f"{self.tool} not installed")

        env = self.environment(dict(base_env), nexus_url, work)
        cmd = self.command(root)
        _log.info("resolve[%s]: %s", self.ecosystem, " ".join(cmd))
        try:
            proc = subprocess.run(  # nosec B603 - argv list, pinned tool, no shell
                cmd, cwd=root, env=env, timeout=timeout,
                capture_output=True, text=True, check=False,
            )
        except subprocess.TimeoutExpired:
            return done(ResolveStatus.FAILED, reason=f"timed out after {timeout}s")
        except OSError as exc:
            return done(ResolveStatus.FAILED, reason=str(exc))

        out = self.produced(root)
        if proc.returncode == 0 and out is not None and out.is_file():
            return done(ResolveStatus.GENERATED, lockfile=out.name)
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return done(ResolveStatus.FAILED,
                    reason=f"exit {proc.returncode}: {tail[-1] if tail else 'no output'}")
