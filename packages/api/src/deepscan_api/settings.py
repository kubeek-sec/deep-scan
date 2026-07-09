"""Environment-driven settings for the REST API.

Follows the core library's conventions (``deepscan_core.config.get`` reads a
``.env`` fallback; real environment variables always win).
"""

from __future__ import annotations

from pathlib import Path

from deepscan_core import config
from deepscan_jobs import config as jobs_config

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # zip uploads


def host() -> str:
    return config.get("DEEPSCAN_API_HOST") or "127.0.0.1"


def port(default: int = 8800) -> int:
    raw = config.get("DEEPSCAN_API_PORT")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return default


def data_dir() -> Path:
    """Shared data dir (reports / targets / uploads). Delegates to
    ``deepscan_jobs`` so the API and MCP server resolve the same location."""
    return jobs_config.data_dir()


def allow_private_targets() -> bool:
    """Whether dynamic scan URLs may point at loopback/private hosts."""
    raw = config.get("DEEPSCAN_ALLOW_PRIVATE_TARGETS")
    return (raw or "").strip().lower() != "false"


def allow_local_paths() -> bool:
    """Whether ``path`` targets on the server filesystem are accepted."""
    raw = config.get("DEEPSCAN_API_ALLOW_LOCAL_PATHS")
    return (raw or "").strip().lower() != "false"
