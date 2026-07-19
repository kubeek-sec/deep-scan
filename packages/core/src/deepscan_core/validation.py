"""Validation of scan targets before they reach any subprocess.

Defends against argument injection (leading-dash paths), escape from the
optional scan root, and obviously malformed DAST URLs.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit

from . import config


class ScanTargetError(ValueError):
    """Raised when a scan target is rejected."""


def resolve_scan_dir(raw: str) -> Path:
    """Canonicalize and validate a directory target for static scans."""
    if not raw or not raw.strip():
        raise ScanTargetError("Empty scan target.")
    raw = raw.strip()
    if raw.startswith("-"):
        raise ScanTargetError("Scan target may not start with '-'.")

    root = config.scan_root()
    if root is None:
        raise ScanTargetError("Local path targets require a configured scan root.")

    candidate = Path(os.path.expanduser(raw))
    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        real = candidate.resolve(strict=True)
    except OSError:
        raise ScanTargetError(f"Scan target does not exist: {candidate}") from None

    if real != root and root not in real.parents:
        raise ScanTargetError(
            f"Scan target {real} is outside the configured scan root {root}."
        )
    if not real.is_dir():
        raise ScanTargetError(f"Scan target is not a directory: {real}")
    return real


def validate_target_url(raw: str, *, allow_private: bool = True) -> str:
    """Validate a URL target for dynamic scans.

    ``allow_private=False`` rejects loopback/private/link-local hosts - used by
    the REST API to avoid being turned into an SSRF proxy when exposed.
    """
    if not raw or not raw.strip():
        raise ScanTargetError("Empty target URL.")
    raw = raw.strip()
    if raw.startswith("-"):
        raise ScanTargetError("Target URL may not start with '-'.")
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ScanTargetError("Target URL must use http:// or https://.")
    if not parts.hostname:
        raise ScanTargetError("Target URL has no host.")
    if parts.username or parts.password:
        raise ScanTargetError("Credentials in the target URL are not allowed.")
    if not allow_private:
        host = parts.hostname
        try:
            addr = ipaddress.ip_address(host)
            if not addr.is_global:
                raise ScanTargetError(f"Non-public target address rejected: {host}")
        except ValueError:
            if host == "localhost" or host.endswith((".local", ".internal")):
                raise ScanTargetError(f"Non-public target host rejected: {host}")
    return raw
