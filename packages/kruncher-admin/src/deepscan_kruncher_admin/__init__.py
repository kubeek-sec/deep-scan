"""deepscan-kruncher-admin - ASPM dashboard and job control plane."""

from __future__ import annotations

from pathlib import Path

__version__ = "0.1.0"


def static_dir() -> Path:
    return Path(__file__).parent / "static"


__all__ = ["static_dir", "__version__"]
