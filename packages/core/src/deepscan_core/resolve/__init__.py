"""Pre-scan dependency resolution.

Generates missing lockfiles (without executing project code) so Trivy SCA sees
the full transitive tree, fully offline. Package managers are pointed at the
Nexus mirror; the subprocess env is stripped of secrets. Public entry point:
:func:`resolve_dependencies`.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..log import get_logger
from .base import Resolver, ResolveResult, ResolveStatus
from .ecosystems import RESOLVERS

__all__ = [
    "resolve_dependencies",
    "Resolver",
    "ResolveResult",
    "ResolveStatus",
    "RESOLVERS",
]

_log = get_logger("resolve")

# Env vars a package manager legitimately needs; everything else (tokens, DB
# creds, cloud/LLM keys) is dropped so a hostile dependency can't read a secret
# out of the environment. This is defense-in-depth on top of the P2 sandbox
# (separate pod, no Secret mounted, Nexus-only egress).
_ENV_ALLOWLIST = (
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "SSL_CERT_FILE", "SSL_CERT_DIR",  # so TLS to Nexus works
    "RUSTUP_HOME",  # the rustup cargo shim needs this to locate its toolchain
)


def _sandbox_env(home: Path) -> dict[str, str]:
    env = {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}
    env["HOME"] = str(home)  # keep managers out of the real ~ (dot-config, creds)
    return env


def resolve_dependencies(
    root: str | Path,
    *,
    nexus_url: str | None = None,
    timeout: int = 300,
    scratch: str | Path | None = None,
    resolvers: list[Resolver] | None = None,
) -> list[ResolveResult]:
    """Run every applicable resolver over ``root`` (the throwaway RAM copy of the
    source), writing any missing lockfiles in place. Best-effort: a resolver that
    fails is recorded and never raises. Returns one result per attempted
    ecosystem (those whose manifest is absent are omitted).

    ``nexus_url`` points package managers at the mirror; ``scratch`` is a base
    dir for per-resolver caches/config (a temp dir is used when omitted).
    """
    root = Path(root)
    resolvers = resolvers if resolvers is not None else RESOLVERS

    def _run(base: Path) -> list[ResolveResult]:
        base.mkdir(parents=True, exist_ok=True)
        results: list[ResolveResult] = []
        for r in resolvers:
            if not r.applies(root):
                continue  # not this ecosystem - stay quiet
            work = base / r.ecosystem
            work.mkdir(parents=True, exist_ok=True)
            res = r.resolve(
                root,
                nexus_url=nexus_url,
                timeout=timeout,
                base_env=_sandbox_env(work),
                work=work,
            )
            if res.status is ResolveStatus.FAILED:
                _log.warning("resolve[%s]: FAILED - %s", res.ecosystem, res.reason)
            else:
                _log.info("resolve[%s]: %s%s", res.ecosystem, res.status.value,
                          f" ({res.lockfile})" if res.lockfile else "")
            results.append(res)
        return results

    if scratch is not None:
        return _run(Path(scratch))
    with tempfile.TemporaryDirectory(prefix="deepscan-resolve-") as tmp:
        return _run(Path(tmp))
