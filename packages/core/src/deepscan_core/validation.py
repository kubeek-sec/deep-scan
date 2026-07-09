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
    path = Path(os.path.abspath(os.path.expanduser(raw)))
    if not path.exists():
        raise ScanTargetError(f"Scan target does not exist: {path}")
    if not path.is_dir():
        raise ScanTargetError(f"Scan target is not a directory: {path}")
    root = config.scan_root()
    if root is not None:
        real = path.resolve()
        if real != root and root not in real.parents:
            raise ScanTargetError(
                f"Scan target {real} is outside the configured scan root {root}."
            )
    return path


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
