"""deepscan-web - static frontend assets for the Deep Scan REST API."""

from pathlib import Path


def static_dir() -> Path:
    return Path(__file__).parent / "static"
