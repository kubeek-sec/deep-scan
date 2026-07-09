"""Admin server settings (env-driven, same conventions as the rest)."""

from __future__ import annotations

from deepscan_core import config


def host() -> str:
    return config.get("DEEPSCAN_ADMIN_HOST") or "127.0.0.1"


def port(default: int = 8900) -> int:
    raw = config.get("DEEPSCAN_ADMIN_PORT")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return default
