"""Defensive git plumbing shared by the git-backed connectors.

Two operations matter to the scheduler:

* :func:`ls_remote_sha` - the cheap change-detection probe. One network round
  trip, no working tree, returns the branch tip SHA.
* :func:`shallow_clone` - the expensive part, run only when the SHA moved.

Both disable credential prompts and system config, reject argument-injection
URLs, and inject a token (when supplied) without ever logging it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import ConnectorAuthError, ConnectorError

_LS_REMOTE_TIMEOUT = 60
_CLONE_TIMEOUT = 600


def _base_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"  # never hang on a credential prompt
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GCM_INTERACTIVE"] = "never"
    return env


def authenticated_url(url: str, *, token: str | None, username: str = "x-access-token") -> str:
    """Embed ``token`` as basic-auth userinfo in an https URL.

    GitHub accepts ``x-access-token:<token>``; GitLab accepts ``oauth2:<token>``.
    No token → the URL is returned unchanged (public clone).
    """
    url = (url or "").strip()
    if url.startswith("-"):
        raise ConnectorError("Git URL may not start with '-'.")
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise ConnectorError("Only http(s) git URLs are supported.")
    if not parts.hostname:
        raise ConnectorError("Git URL has no host.")
    if not token:
        return url
    host = parts.hostname + (f":{parts.port}" if parts.port else "")
    netloc = f"{username}:{token}@{host}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _run_git(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_base_env(),
        check=False,
    )


def _scrub(text: str, token: str | None) -> str:
    text = text.strip()[:500]
    if token:
        text = text.replace(token, "***")
    return text


def ls_remote_sha(
    url: str, branch: str | None, *, token: str | None = None, username: str = "x-access-token"
) -> str | None:
    """Return the tip SHA of ``branch`` (or HEAD) without cloning.

    ``None`` is returned when the ref does not exist. Auth failures raise
    :class:`ConnectorAuthError`.
    """
    auth_url = authenticated_url(url, token=token, username=username)
    ref = f"refs/heads/{branch}" if branch else "HEAD"
    result = _run_git(["ls-remote", "--", auth_url, ref], timeout=_LS_REMOTE_TIMEOUT)
    if result.returncode != 0:
        err = _scrub(result.stderr, token)
        if "Authentication failed" in err or "could not read Username" in err or "403" in err:
            raise ConnectorAuthError(f"git ls-remote auth failed: {err}")
        raise ConnectorError(f"git ls-remote failed: {err}")
    line = result.stdout.strip().splitlines()
    if not line:
        return None
    return line[0].split("\t", 1)[0].strip() or None


def shallow_clone(
    url: str,
    dest: Path,
    *,
    branch: str | None = None,
    token: str | None = None,
    username: str = "x-access-token",
) -> Path:
    """Shallow single-branch clone into ``dest`` (must not already exist)."""
    auth_url = authenticated_url(url, token=token, username=username)
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["clone", "--depth", "1", "--single-branch"]
    if branch:
        args += ["--branch", branch]
    args += ["--", auth_url, str(dest)]
    result = _run_git(args, timeout=_CLONE_TIMEOUT)
    if result.returncode != 0:
        err = _scrub(result.stderr, token)
        if "Authentication failed" in err or "could not read Username" in err:
            raise ConnectorAuthError(f"git clone auth failed: {err}")
        raise ConnectorError(f"git clone failed: {err}")
    return dest
