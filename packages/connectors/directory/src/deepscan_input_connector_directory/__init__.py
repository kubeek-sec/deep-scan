"""Directory input connector.

Wraps a directory the server can already read - any contents, not only git
checkouts (NFS mount, an unpacked artifact, a shared volume). Scope config::

    {
      "base_path": "/data/projects",   # required, must exist on the server
      "layout": "subdirs",             # "subdirs" (default): each immediate
                                       #   child dir is a source;
                                       # "single": base_path itself is one source
      "include_hidden": false,         # include dot-directories (subdirs layout)
      "name_regex": "^svc-",           # optional filter on the child dir name
      "snapshot": false                # true: copy into a scratch dir before
                                       #   scanning (consistent view); false:
                                       #   scan in place read-only (cheaper)
    }

Change detection is a content-free signature over ``(path, size, mtime)`` so a
re-scan only happens when files were added, removed, edited or touched.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from deepscan_input_connector_base import (
    KIND_DIRECTORY,
    ConnectorConfigError,
    ConnectorError,
    DiscoveredSource,
    directory_signature,
    register,
)

_IGNORE_COPY = shutil.ignore_patterns(
    ".git", "node_modules", ".venv", "__pycache__", "*.pyc"
)


class DirectoryConnector:
    name = "directory"

    def validate_config(self, config: dict[str, Any]) -> None:
        base = config.get("base_path")
        if not base:
            raise ConnectorConfigError("directory scope needs 'base_path'.")
        path = Path(str(base)).expanduser()
        if not path.is_dir():
            raise ConnectorConfigError(f"base_path is not a directory: {path}")
        layout = config.get("layout", "subdirs")
        if layout not in ("subdirs", "single"):
            raise ConnectorConfigError("layout must be 'subdirs' or 'single'.")
        if regex := config.get("name_regex"):
            try:
                re.compile(regex)
            except re.error as exc:
                raise ConnectorConfigError(f"invalid name_regex: {exc}") from exc

    def discover(self, config: dict[str, Any]) -> Iterable[DiscoveredSource]:
        self.validate_config(config)
        base = Path(str(config["base_path"])).expanduser().resolve()
        layout = config.get("layout", "subdirs")
        if layout == "single":
            yield self._source(base, base.name or str(base))
            return
        include_hidden = bool(config.get("include_hidden", False))
        name_regex = re.compile(config["name_regex"]) if config.get("name_regex") else None
        for child in sorted(base.iterdir()):
            if not child.is_dir() or child.is_symlink():
                continue
            if child.name.startswith(".") and not include_hidden:
                continue
            if name_regex and not name_regex.search(child.name):
                continue
            yield self._source(child.resolve(), child.name)

    def current_revision(
        self, source: DiscoveredSource, config: dict[str, Any]
    ) -> str | None:
        path = Path(source.location)
        if not path.is_dir():
            return None
        return directory_signature(path)

    def materialize(
        self,
        source: DiscoveredSource,
        revision: str | None,
        dest: Path,
        config: dict[str, Any],
    ) -> Path:
        path = Path(source.location)
        if not path.is_dir():
            raise ConnectorError(f"directory source vanished: {path}")
        if not config.get("snapshot", False):
            return path  # scan in place (read-only); cheapest
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(path, dest, ignore=_IGNORE_COPY, symlinks=False, dirs_exist_ok=False)
        return dest

    def _source(self, path: Path, name: str) -> DiscoveredSource:
        return DiscoveredSource(
            external_id=str(path),
            kind=KIND_DIRECTORY,
            name=name,
            location=str(path),
            default_branch=None,
            metadata={},
        )


CONNECTOR = register(DirectoryConnector())

__all__ = ["DirectoryConnector", "CONNECTOR"]
