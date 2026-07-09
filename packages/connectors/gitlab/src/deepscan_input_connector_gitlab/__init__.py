"""GitLab input connector.

Scope config (one of ``group`` / ``user`` is required)::

    {
      "group": "my-group/sub",         # group full path or numeric id, OR
      "user": "some-user",             # a user account
      "base_url": "https://gitlab.com",       # self-managed: your instance URL
      "token_env": "GITLAB_TOKEN",     # env var holding a PAT (read_api + read_repository)
      "include_subgroups": true,       # default true (groups only)
      "include_archived": false,       # default false
      "name_regex": "^infra-"          # optional client-side filter on path
    }

Discovery enumerates projects (paginated via ``X-Next-Page``) and yields a git
source per project. Cloning uses ``oauth2:<token>`` basic-auth.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
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

_DEFAULT_BASE_URL = "https://gitlab.com"
_PAGE_SIZE = 100
_HTTP_TIMEOUT = 30
_USER_AGENT = "deepscan-input-connector-gitlab/0.1"
_GIT_USERNAME = "oauth2"


class GitLabConnector:
    name = "gitlab"

    def validate_config(self, config: dict[str, Any]) -> None:
        if not config.get("group") and not config.get("user"):
            raise ConnectorConfigError("gitlab scope needs either 'group' or 'user'.")
        if config.get("group") and config.get("user"):
            raise ConnectorConfigError("gitlab scope: set only one of 'group'/'user'.")
        if regex := config.get("name_regex"):
            try:
                re.compile(regex)
            except re.error as exc:
                raise ConnectorConfigError(f"invalid name_regex: {exc}") from exc

    def discover(self, config: dict[str, Any]) -> Iterable[DiscoveredSource]:
        self.validate_config(config)
        token = token_from_env(config.get("token_env"))
        base = (config.get("base_url") or _DEFAULT_BASE_URL).rstrip("/")
        include_archived = bool(config.get("include_archived", False))
        name_regex = re.compile(config["name_regex"]) if config.get("name_regex") else None

        if config.get("group"):
            ident = urllib.parse.quote(str(config["group"]), safe="")
            params = {
                "per_page": _PAGE_SIZE,
                "include_subgroups": str(
                    bool(config.get("include_subgroups", True))
                ).lower(),
                "archived": "false" if not include_archived else "",
                "with_shared": "false",
            }
            path = f"/api/v4/groups/{ident}/projects"
        else:
            ident = urllib.parse.quote(str(config["user"]), safe="")
            params = {"per_page": _PAGE_SIZE}
            path = f"/api/v4/users/{ident}/projects"
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v != ""})
        url = f"{base}{path}?{query}"

        for project in self._paginate(url, token):
            if project.get("archived") and not include_archived:
                continue
            full = project.get("path_with_namespace") or project.get("name") or ""
            if name_regex and not name_regex.search(full):
                continue
            yield DiscoveredSource(
                external_id=str(project.get("id") or full),
                kind=KIND_GIT,
                name=full,
                location=project.get("http_url_to_repo") or "",
                default_branch=project.get("default_branch") or "main",
                metadata={
                    "project_id": project.get("id"),
                    "visibility": project.get("visibility"),
                    "web_url": project.get("web_url"),
                    "token_env": config.get("token_env"),
                },
            )

    def current_revision(
        self, source: DiscoveredSource, config: dict[str, Any]
    ) -> str | None:
        token = token_from_env(config.get("token_env"))
        return ls_remote_sha(
            source.location, source.default_branch, token=token, username=_GIT_USERNAME
        )

    def materialize(
        self,
        source: DiscoveredSource,
        revision: str | None,
        dest: Path,
        config: dict[str, Any],
    ) -> Path:
        token = token_from_env(config.get("token_env"))
        return shallow_clone(
            source.location,
            dest,
            branch=source.default_branch,
            token=token,
            username=_GIT_USERNAME,
        )

    def _paginate(self, url: str | None, token: str | None) -> Iterator[dict[str, Any]]:
        while url:
            body, next_url = self._get(url, token)
            if isinstance(body, list):
                yield from (item for item in body if isinstance(item, dict))
            url = next_url

    def _get(self, url: str, token: str | None) -> tuple[Any, str | None]:
        request = urllib.request.Request(url, method="GET")
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", _USER_AGENT)
        if token:
            request.add_header("PRIVATE-TOKEN", token)
        try:
            with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                next_page = resp.headers.get("X-Next-Page")
                next_url = _with_page(url, next_page) if next_page else None
                return payload, next_url
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise ConnectorAuthError(
                    f"GitLab API {exc.code} for {_redact(url)}: check token/scopes."
                ) from exc
            raise ConnectorError(f"GitLab API {exc.code} for {_redact(url)}.") from exc
        except urllib.error.URLError as exc:
            raise ConnectorError(f"GitLab API unreachable: {exc.reason}") from exc


def _with_page(url: str, page: str) -> str:
    parts = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parts.query))
    query["page"] = page
    new_query = urllib.parse.urlencode(query)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)
    )


def _redact(url: str) -> str:
    return url.split("?", 1)[0]


CONNECTOR = register(GitLabConnector())

__all__ = ["GitLabConnector", "CONNECTOR"]
