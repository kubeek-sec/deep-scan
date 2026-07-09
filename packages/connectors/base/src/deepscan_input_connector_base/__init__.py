"""Deep Scan input-connector contract.

A **connector** turns a *scope* (an organization, a group, a directory) into a
set of concrete, scannable **sources** and knows how to (a) cheaply detect
whether a source has changed and (b) materialize it into a local directory the
core scanner can run over.

The three responsibilities are deliberately separated so the scheduler can do
the cheap part (`discover` + `current_revision`) often and the expensive part
(`materialize` + scan) only when something actually changed.

    discover(config)        -> [DiscoveredSource, ...]      # list what exists
    current_revision(src)   -> "abc123" | None              # cheap change token
    materialize(src, rev)   -> Path                          # local copy to scan

Connectors self-register via :func:`register`; front-ends resolve them by name
with :func:`get` / :func:`available`.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

__version__ = "0.1.0"


class ConnectorError(Exception):
    """A connector could not complete an operation (network, parse, IO)."""


class ConnectorAuthError(ConnectorError):
    """Authentication/authorization failed (missing or rejected token)."""


class ConnectorConfigError(ConnectorError, ValueError):
    """The scope configuration handed to the connector is invalid."""


# Source kinds understood by the kruncher/scanner.
KIND_GIT = "git"
KIND_DIRECTORY = "directory"


@dataclass(frozen=True)
class DiscoveredSource:
    """One scannable thing found inside a scope.

    ``external_id`` is stable for the lifetime of the source within its
    connector (e.g. a repo's full name or a directory's absolute path) and is
    what the store keys on to detect appearances/disappearances across
    discoveries.
    """

    external_id: str
    kind: str  # KIND_GIT | KIND_DIRECTORY
    name: str
    location: str  # git clone URL, or absolute filesystem path
    default_branch: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in (KIND_GIT, KIND_DIRECTORY):
            raise ConnectorConfigError(f"Unknown source kind {self.kind!r}.")
        if not self.external_id:
            raise ConnectorConfigError("DiscoveredSource.external_id is required.")


@runtime_checkable
class Connector(Protocol):
    """The contract every input connector implements."""

    name: str

    def validate_config(self, config: dict[str, Any]) -> None:
        """Raise :class:`ConnectorConfigError` if ``config`` is unusable."""
        ...

    def discover(self, config: dict[str, Any]) -> Iterable[DiscoveredSource]:
        """List the sources currently present in the scope."""
        ...

    def current_revision(
        self, source: DiscoveredSource, config: dict[str, Any]
    ) -> str | None:
        """A cheap token identifying the source's current state.

        Git: the commit SHA of the tracked branch (one ``ls-remote``, no clone).
        Directory: a signature over ``(path, size, mtime)`` - no file contents
        are read. ``None`` means "unknown / always rescan".
        """
        ...

    def materialize(
        self,
        source: DiscoveredSource,
        revision: str | None,
        dest: Path,
        config: dict[str, Any],
    ) -> Path:
        """Produce a local directory to scan; return the path handed to core.

        May return ``dest`` (a fresh checkout/copy) or, for already-local
        directory sources, the source path itself.
        """
        ...


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_REGISTRY: dict[str, Connector] = {}


def register(connector: Connector) -> Connector:
    """Register a connector instance under its ``name`` (idempotent)."""
    _REGISTRY[connector.name] = connector
    return connector


def get(name: str) -> Connector:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ConnectorConfigError(
            f"Unknown connector {name!r}. Available: {', '.join(available()) or '(none)'}"
        ) from None


def available() -> list[str]:
    return sorted(_REGISTRY)


# --------------------------------------------------------------------------- #
# Shared helpers (used by the git/directory connectors)
# --------------------------------------------------------------------------- #


def token_from_env(env_name: str | None) -> str | None:
    """Read a token from the named environment variable, if set and non-empty."""
    if not env_name:
        return None
    value = os.environ.get(env_name, "").strip()
    return value or None


def directory_signature(
    root: Path,
    *,
    ignore_dirs: frozenset[str] = frozenset({".git", "node_modules", ".venv", "__pycache__"}),
    max_entries: int = 200_000,
) -> str:
    """A content-free signature of a directory tree.

    Hashes the sorted ``(relative_path, size, mtime_ns)`` of every file without
    opening any of them, so a re-run is cheap and changes (add/remove/edit/touch)
    flip the signature. Bounded by ``max_entries`` to stay predictable.
    """
    root = root.resolve()
    digest = hashlib.sha256()
    count = 0
    for path in _walk_files(root, ignore_dirs):
        try:
            st = path.stat()
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        digest.update(f"{rel}\0{st.st_size}\0{st.st_mtime_ns}\n".encode("utf-8", "replace"))
        count += 1
        if count >= max_entries:
            digest.update(b"\0truncated")
            break
    digest.update(f"\0count={count}".encode())
    return digest.hexdigest()[:40]


def _walk_files(root: Path, ignore_dirs: frozenset[str]) -> Iterator[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in ignore_dirs:
                    stack.append(Path(entry.path))
            elif entry.is_file(follow_symlinks=False):
                yield Path(entry.path)


__all__ = [
    "__version__",
    "Connector",
    "DiscoveredSource",
    "ConnectorError",
    "ConnectorAuthError",
    "ConnectorConfigError",
    "KIND_GIT",
    "KIND_DIRECTORY",
    "register",
    "get",
    "available",
    "token_from_env",
    "directory_signature",
]
