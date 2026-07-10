#!/usr/bin/env python3
"""Provision Nexus pull-through *proxy* repositories for every package ecosystem
the dependency resolver supports - idempotently, over the Nexus REST API.

The resolver points package managers (npm/pip/go/cargo/gem/maven) at these
repos instead of the public registries, so the scan sandbox needs no direct
internet and Nexus caches artifacts (killing the Maven Central 429s).

Run once after Nexus is up (a one-shot Job / compose service). Safe to re-run:
existing repos are left as-is.

  NEXUS_URL       base URL of Nexus            (default http://nexus:8081)
  NEXUS_USER      admin user                   (default admin)
  NEXUS_PASSWORD  admin password               (REQUIRED - first-boot password
                  is in <nexus-data>/admin.password)

Only the standard library is used so it runs on a bare `python:3-slim` image.

NOTE: validated against Nexus Repository 3.70.x. Cargo proxy needs Nexus >= 3.63.
Composer/Packagist is intentionally absent: Nexus OSS has no native `composer`
format. Composer projects are handled out-of-band (see deploy/nexus/README.md).
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

# (nexus format, repo name, remote registry URL). The repo name is also the path
# segment package managers use: e.g. http://nexus:8081/repository/<name>/.
# All seven formats provision on Nexus 3.94.0. (cargo was absent on 3.70.1; the
# 404 -> unsupported-format skip below keeps this script safe on older Nexus.)
REPOS: list[tuple[str, str, str]] = [
    ("maven2", "maven-central", "https://repo1.maven.apache.org/maven2/"),
    ("npm", "npm-proxy", "https://registry.npmjs.org"),
    ("pypi", "pypi-proxy", "https://pypi.org/"),
    ("nuget", "nuget-proxy", "https://api.nuget.org/v3/index.json"),
    ("rubygems", "rubygems-proxy", "https://rubygems.org"),
    ("go", "go-proxy", "https://proxy.golang.org"),
    ("cargo", "cargo-proxy", "https://crates.io"),
]

NEXUS_URL = os.environ.get("NEXUS_URL", "http://nexus:8081").rstrip("/")
NEXUS_USER = os.environ.get("NEXUS_USER", "admin")
NEXUS_PASSWORD = os.environ.get("NEXUS_PASSWORD", "")
BOOT_TIMEOUT = int(os.environ.get("NEXUS_BOOT_TIMEOUT", "600"))  # seconds


def _auth_header() -> str:
    raw = f"{NEXUS_USER}:{NEXUS_PASSWORD}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _request(method: str, path: str, body: dict | None = None) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{NEXUS_URL}{path}", data=data, method=method)
    req.add_header("Authorization", _auth_header())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - internal URL
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_for_nexus() -> None:
    """Block until Nexus answers /status (it boots slowly, ~1-2 min)."""
    deadline = time.monotonic() + BOOT_TIMEOUT
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(  # nosec B310 - internal URL
                f"{NEXUS_URL}/service/rest/v1/status", timeout=10
            ) as resp:
                if resp.status == 200:
                    print(f"Nexus is up at {NEXUS_URL}", flush=True)
                    return
        except (urllib.error.URLError, OSError) as exc:
            print(f"waiting for Nexus... ({exc})", flush=True)
        time.sleep(5)
    sys.exit(f"ERROR: Nexus did not become ready within {BOOT_TIMEOUT}s")


def existing_repo_names() -> set[str]:
    status, body = _request("GET", "/service/rest/v1/repositories")
    if status != 200:
        sys.exit(f"ERROR: listing repositories failed ({status}): {body.decode()[:300]}")
    return {r["name"] for r in json.loads(body)}


def enable_anonymous_access() -> None:
    """Nexus 3.94 ships with anonymous access DISABLED, so package managers get
    401s from the proxy repos. This mirror is internal (locked down by
    NetworkPolicy), so anonymous *read* is the right trade-off - enable it."""
    status, _ = _request(
        "PUT", "/service/rest/v1/security/anonymous",
        {"enabled": True, "userId": "anonymous", "realmName": "NexusAuthorizingRealm"},
    )
    if status == 200:
        print("+ anonymous read access enabled", flush=True)
    else:
        print(f"! WARNING: could not enable anonymous access ({status}) - "
              f"package managers may get 401s", flush=True)


def repo_body(fmt: str, name: str, remote: str) -> dict:
    body: dict = {
        "name": name,
        "online": True,
        "storage": {"blobStoreName": "default", "strictContentTypeValidation": True},
        "proxy": {"remoteUrl": remote, "contentMaxAge": 1440, "metadataMaxAge": 1440},
        "negativeCache": {"enabled": True, "timeToLive": 1440},
        "httpClient": {"blocked": False, "autoBlock": True},
    }
    if fmt == "maven2":
        body["maven"] = {"versionPolicy": "MIXED", "layoutPolicy": "PERMISSIVE",
                         "contentDisposition": "ATTACHMENT"}
    elif fmt == "nuget":
        body["nugetProxy"] = {"nugetVersion": "V3", "queryCacheItemMaxAge": 3600}
    return body


def main() -> None:
    if not NEXUS_PASSWORD:
        sys.exit("ERROR: NEXUS_PASSWORD is required (see <nexus-data>/admin.password)")
    wait_for_nexus()
    enable_anonymous_access()
    existing = existing_repo_names()
    created, skipped, unsupported, failed = 0, 0, 0, 0
    for fmt, name, remote in REPOS:
        if name in existing:
            print(f"= {name} ({fmt}) already exists, leaving as-is", flush=True)
            skipped += 1
            continue
        status, resp = _request(
            "POST", f"/service/rest/v1/repositories/{fmt}/proxy", repo_body(fmt, name, remote)
        )
        if status in (200, 201):
            print(f"+ created {name} ({fmt}) -> {remote}", flush=True)
            created += 1
        elif status == 404:
            # The REST path pattern is shared by all formats, so a 404 means this
            # Nexus edition/version does not support the `{fmt}` format - a known
            # limitation, not an error (e.g. cargo on Nexus < the cargo release).
            print(f"~ skipped {name} ({fmt}): format not supported by this Nexus", flush=True)
            unsupported += 1
        else:
            print(f"! FAILED {name} ({fmt}): {status} {resp.decode()[:300]}", flush=True)
            failed += 1
    print(f"\ndone: {created} created, {skipped} existing, "
          f"{unsupported} unsupported, {failed} failed", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
