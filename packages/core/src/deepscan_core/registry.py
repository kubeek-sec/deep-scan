"""Scanner registry and selection."""

from __future__ import annotations

from .models import Family, Mode
from .scanners import ALL_SCANNERS, Scanner

REGISTRY: dict[str, Scanner] = {s.name: s for s in ALL_SCANNERS}


class UnknownScannerError(ValueError):
    pass


def get(name: str) -> Scanner:
    scanner = REGISTRY.get(name)
    if scanner is None:
        raise UnknownScannerError(
            f"Unknown scanner {name!r}. Available: {', '.join(sorted(REGISTRY))}"
        )
    return scanner


def select(
    mode: Mode | None = None,
    families: list[Family] | None = None,
    names: list[str] | None = None,
) -> list[Scanner]:
    """Filter the registry: explicit names win, then family filter, then mode."""
    if names:
        return [get(n) for n in names]
    scanners = list(REGISTRY.values())
    if families:
        scanners = [s for s in scanners if s.family in families]
    if mode is not None:
        scanners = [s for s in scanners if s.mode == mode]
    return scanners


def describe() -> list[dict[str, str]]:
    return [
        {
            "name": s.name,
            "family": s.family.value,
            "mode": s.mode.value,
            "tool": s.tool or "",
            "description": s.description,
        }
        for s in sorted(REGISTRY.values(), key=lambda s: (s.family.value, s.name))
    ]
