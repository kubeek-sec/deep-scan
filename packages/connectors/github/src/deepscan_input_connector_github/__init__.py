"""GitHub input connector.

Scope config (one of ``org`` / ``user`` is required)::

    {
      "org": "my-org",                 # organization to enumerate, OR
      "user": "octocat",               # a user account
      "base_url": "https://api.github.com",   # optional, for GitHub Enterprise
      "token_env": "GITHUB_TOKEN",     # env var holding a PAT (optional but
                                       #   required for private repos / rate limit)
      "include_archived": false,       # default false
      "include_forks": false,          # default false
      "name_regex": "^team-"           # optional client-side repo filter
    }

Discovery lists repositories (paginated) and turns each into a git source whose
default branch is the repo's ``default_branch``. Change detection and cloning
go through the shared ``git_support`` helpers, so only the default branch is
ever fetched.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from deepscan_input_connector_base import (
    KIND_GIT,
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
    DiscoveredSource,
    register,
    token_from_env,
)
from deepscan_input_connector_base.git_support import ls_remote_sha, shallow_clone

_DEFAULT_BASE_URL = "https://api.github.com"
_PAGE_SIZE = 100
_HTTP_TIMEOUT = 30
_USER_AGENT = "deepscan-input-connector-github/0.1"


class GitHubConnector:
    name = "github"

    # -- config ------------------------------------------------------------- #

    def validate_config(self, config: dict[str, Any]) -> None:
        if not config.get("org") and not config.get("user"):
            raise ConnectorConfigError("github scope needs either 'org' or 'user'.")
        if config.get("org") and config.get("user"):
            raise ConnectorConfigError("github scope: set only one of 'org'/'user'.")
        if regex := config.get("name_regex"):
            try:
                re.compile(regex)
            except re.error as exc:
                raise ConnectorConfigError(f"invalid name_regex: {exc}") from exc

    # -- discovery ---------------------------------------------------------- #

    def discover(self, config: dict[str, Any]) -> Iterable[DiscoveredSource]:
        self.validate_config(config)
        token = token_from_env(config.get("token_env"))
        base = (config.get("base_url") or _DEFAULT_BASE_URL).rstrip("/")
        if config.get("org"):
            path = f"/orgs/{config['org']}/repos"
        else:
            path = f"/users/{config['user']}/repos"
        include_archived = bool(config.get("include_archived", False))
        include_forks = bool(config.get("include_forks", False))
        name_regex = re.compile(config["name_regex"]) if config.get("name_regex") else None

        for repo in self._paginate(f"{base}{path}?per_page={_PAGE_SIZE}&type=all", token):
            if repo.get("archived") and not include_archived:
                continue
            if repo.get("fork") and not include_forks:
                continue
            name = repo.get("name") or ""
            if name_regex and not name_regex.search(name):
                continue
            full = repo.get("full_name") or name
            yield DiscoveredSource(
                external_id=full,
                kind=KIND_GIT,
                name=full,
                location=repo.get("clone_url") or "",
                default_branch=repo.get("default_branch") or "main",
                metadata={
                    "private": bool(repo.get("private")),
                    "archived": bool(repo.get("archived")),
                    "html_url": repo.get("html_url"),
                    "language": repo.get("language"),
                    "token_env": config.get("token_env"),
                },
            )

    # -- change detection / fetch ------------------------------------------ #

    def current_revision(
        self, source: DiscoveredSource, config: dict[str, Any]
    ) -> str | None:
        token = token_from_env(config.get("token_env"))
        return ls_remote_sha(source.location, source.default_branch, token=token)

    def materialize(
        self,
        source: DiscoveredSource,
        revision: str | None,
        dest: Path,
        config: dict[str, Any],
    ) -> Path:
        token = token_from_env(config.get("token_env"))
        return shallow_clone(
            source.location, dest, branch=source.default_branch, token=token
        )

    # -- internals ---------------------------------------------------------- #

    def _paginate(self, url: str | None, token: str | None) -> Iterator[dict[str, Any]]:
        while url:
            body, next_url = self._get(url, token)
            if isinstance(body, list):
                yield from (item for item in body if isinstance(item, dict))
            url = next_url

    def _get(self, url: str, token: str | None) -> tuple[Any, str | None]:
        request = urllib.request.Request(url, method="GET")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("User-Agent", _USER_AGENT)
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                return payload, _next_link(resp.headers.get("Link"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise ConnectorAuthError(
                    f"GitHub API {exc.code} for {_redact(url)}: check token/scopes."
                ) from exc
            raise ConnectorError(f"GitHub API {exc.code} for {_redact(url)}.") from exc
        except urllib.error.URLError as exc:
            raise ConnectorError(f"GitHub API unreachable: {exc.reason}") from exc


def _next_link(link_header: str | None) -> str | None:
    """Parse RFC 5988 ``Link`` header for the ``rel="next"`` URL."""
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        url = section[0].strip().lstrip("<").rstrip(">")
        if any(rel.strip() == 'rel="next"' for rel in section[1:]):
            return url
    return None


def _redact(url: str) -> str:
    return url.split("?", 1)[0]


CONNECTOR = register(GitHubConnector())

__all__ = ["GitHubConnector", "CONNECTOR"]
