"""Centralized logging for Deep Scan.

All scanners, the runner and the engines log under the ``deepscan.*`` namespace.
A front-end calls :func:`setup_logging` once to attach a stderr handler; library
use stays quiet (a NullHandler) until then.

Level: INFO by default, DEBUG via ``DEEPSCAN_DEBUG=1`` or
``DEEPSCAN_LOG_LEVEL=DEBUG`` (see ``config.log_level_name``). Logs go to
**stderr** so stdout stays reserved for report output.
"""

from __future__ import annotations

import logging
import sys

from . import config

_ROOT = "deepscan"
_configured = False

# Quiet by default for library use; setup_logging() replaces this.
logging.getLogger(_ROOT).addHandler(logging.NullHandler())


def get_logger(name: str) -> logging.Logger:
    """Logger for a component, e.g. ``get_logger("scanner")`` →
    ``deepscan.scanner``."""
    return logging.getLogger(f"{_ROOT}.{name}")


def setup_logging(level: str | None = None, *, force: bool = False) -> None:
    """Attach a stderr handler to the ``deepscan`` logger. Idempotent unless
    *force*. *level* overrides the env-derived level (e.g. a CLI ``--debug``)."""
    global _configured
    if _configured and not force:
        if level:
            logging.getLogger(_ROOT).setLevel(_resolve(level))
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-5s %(name)s: %(message)s", "%H:%M:%S")
    )
    root = logging.getLogger(_ROOT)
    for h in list(root.handlers):
        if not isinstance(h, logging.NullHandler):
            root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(_resolve(level or config.log_level_name()))
    root.propagate = False
    _configured = True


def _resolve(name: str) -> int:
    return getattr(logging, name.upper(), logging.INFO) if isinstance(name, str) else name
