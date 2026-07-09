"""Direct git-URL input connector.

The simplest possible scope: one (or a few) git repository URLs, with **no org
or group to enumerate** and **no token required** for public repos. Scope
config::

    { "url": "https://github.com/michoo/flanby" }          # single repo

    {                                                        # several, with auth
      "urls": [
        "https://github.com/acme/api",
        "https://gitlab.com/acme/infra"
      ],
      "branch": "main",                 # optional: pin a branch (default: remote HEAD)
      "token_env": "GITHUB_TOKEN",      # optional: env var holding a PAT
      "auth_username": "x-access-token" # optional: "x-access-token" (GitHub, default)
                                        #           or "oauth2" (GitLab)
    }

When ``token_env`` is omitted (or the variable is empty) the repo is cloned
anonymously - fine for public repositories. The token, when present, is read
from the environment at run time and never stored in the database.

Change detection is ``git ls-remote`` (HEAD, or the pinned branch); cloning is
a shallow single-branch clone. Works against github.com, gitlab.com and any
self-managed git host over http(s).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from deepscan_input_connector_base import (
    KIND_GIT,
    ConnectorConfigError,
    DiscoveredSource,
    register,
    token_from_env,
)
from deepscan_input_connector_base.git_support import ls_remote_sha, shallow_clone

_DEFAULT_AUTH_USERNAME = "x-access-token"


class GitConnector:
    name = "git"

    def _urls(self, config: dict[str, Any]) -> list[str]:
        urls: list[str] = []
        if config.get("url"):
            urls.append(str(config["url"]).strip())
        for u in config.get("urls", []) or []:
            if u and str(u).strip():
                urls.append(str(u).strip())
        return urls

    def validate_config(self, config: dict[str, Any]) -> None:
        urls = self._urls(config)
        if not urls:
            raise ConnectorConfigError("git scope needs 'url' or 'urls'.")
        for url in urls:
            parts = urlsplit(url)
            if parts.scheme not in ("https", "http"):
                raise ConnectorConfigError(f"git URL must be http(s): {url!r}")
            if not parts.hostname:
                raise ConnectorConfigError(f"git URL has no host: {url!r}")

    def discover(self, config: dict[str, Any]) -> Iterable[DiscoveredSource]:
        self.validate_config(config)
        branch = config.get("branch") or None
        for url in self._urls(config):
            yield DiscoveredSource(
                external_id=url,
                kind=KIND_GIT,
                name=_repo_name(url),
                location=url,
                default_branch=branch,  # None -> remote default branch
                metadata={
                    "token_env": config.get("token_env"),
                    "auth_username": config.get("auth_username"),
                },
            )

    def current_revision(
        self, source: DiscoveredSource, config: dict[str, Any]
    ) -> str | None:
        return ls_remote_sha(
            source.location,
            source.default_branch,
            token=token_from_env(config.get("token_env")),
            username=config.get("auth_username") or _DEFAULT_AUTH_USERNAME,
        )

    def materialize(
        self,
        source: DiscoveredSource,
        revision: str | None,
        dest: Path,
        config: dict[str, Any],
    ) -> Path:
        return shallow_clone(
            source.location,
            dest,
            branch=source.default_branch,
            token=token_from_env(config.get("token_env")),
            username=config.get("auth_username") or _DEFAULT_AUTH_USERNAME,
        )


def _repo_name(url: str) -> str:
    """Human label from a clone URL, e.g. ``michoo/flanby`` from its GitHub URL."""
    path = urlsplit(url).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return path or url


CONNECTOR = register(GitConnector())

__all__ = ["GitConnector", "CONNECTOR"]
