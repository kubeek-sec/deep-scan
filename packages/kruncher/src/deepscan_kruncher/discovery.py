"""Scope discovery: ask a connector what sources exist, reconcile the store.

Newly seen sources are inserted, returning ones are refreshed and reactivated,
and sources that disappeared from the scope are marked inactive (kept, not
deleted, so their history survives).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from . import store
from .connectors import get as get_connector

log = logging.getLogger("deepscan.kruncher.discovery")


@dataclass
class DiscoveryOutcome:
    scope: str
    discovered: int
    deactivated: int
    error: str | None = None


def refresh_scope(scope: dict[str, Any]) -> DiscoveryOutcome:
    """Run discovery for one scope row and reconcile its sources."""
    connector = get_connector(scope["connector"])
    seen: list[str] = []
    try:
        for source in connector.discover(scope["config"]):
            store.upsert_source(scope["id"], source)
            seen.append(source.external_id)
    except Exception as exc:  # noqa: BLE001 - surface as outcome, never crash the loop
        log.warning("Discovery failed for scope %s: %s", scope["name"], exc)
        return DiscoveryOutcome(scope["name"], len(seen), 0, error=str(exc)[:500])

    deactivated = store.deactivate_missing_sources(scope["id"], seen)
    store.mark_scope_discovered(scope["id"])
    log.info(
        "Discovered scope %s: %d source(s), %d deactivated.",
        scope["name"],
        len(seen),
        deactivated,
    )
    return DiscoveryOutcome(scope["name"], len(seen), deactivated)


def refresh_scope_by_name(name: str) -> DiscoveryOutcome:
    scope = store.get_scope_by_name(name)
    if scope is None:
        raise ValueError(f"No scope named {name!r}.")
    return refresh_scope(scope)
