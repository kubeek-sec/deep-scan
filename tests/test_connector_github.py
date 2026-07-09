"""GitHub connector tests - HTTP is monkeypatched, no network is touched."""

from __future__ import annotations

import pytest

from deepscan_input_connector_base import ConnectorConfigError
from deepscan_input_connector_github import GitHubConnector, _next_link


def _repo(name, **kw):
    base = {
        "name": name,
        "full_name": f"acme/{name}",
        "clone_url": f"https://github.com/acme/{name}.git",
        "default_branch": "main",
        "private": False,
        "archived": False,
        "fork": False,
    }
    base.update(kw)
    return base


def test_next_link_parsing():
    header = '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"'
    assert _next_link(header) == "https://api.github.com/x?page=2"
    assert _next_link(None) is None
    assert _next_link('<https://x>; rel="last"') is None


def test_validate_config():
    c = GitHubConnector()
    with pytest.raises(ConnectorConfigError):
        c.validate_config({})  # neither org nor user
    with pytest.raises(ConnectorConfigError):
        c.validate_config({"org": "a", "user": "b"})  # both
    with pytest.raises(ConnectorConfigError):
        c.validate_config({"org": "a", "name_regex": "([bad"})
    c.validate_config({"org": "acme"})  # ok


def test_discover_paginates_and_filters(monkeypatch):
    c = GitHubConnector()
    pages = {
        "p1": ([_repo("api"), _repo("old", archived=True), _repo("forked", fork=True)], "p2"),
        "p2": ([_repo("web"), _repo("legacy-svc")], None),
    }

    def fake_get(url, token):
        return pages["p2"] if "p2" in url else pages["p1"]

    # first call uses the assembled url (no 'p2'); chain by returning next='p2'
    monkeypatch.setattr(GitHubConnector, "_get", lambda self, url, token: fake_get(url, token))

    sources = list(c.discover({"org": "acme", "name_regex": "^(api|web)$"}))
    names = sorted(s.name for s in sources)
    # archived + fork excluded by default; name_regex keeps api & web only
    assert names == ["acme/api", "acme/web"]
    assert all(s.kind == "git" and s.default_branch == "main" for s in sources)
    assert sources[0].location.endswith(".git")


def test_discover_includes_archived_when_asked(monkeypatch):
    c = GitHubConnector()
    monkeypatch.setattr(
        GitHubConnector,
        "_get",
        lambda self, url, token: ([_repo("a"), _repo("b", archived=True)], None),
    )
    names = sorted(s.name for s in c.discover({"org": "acme", "include_archived": True}))
    assert names == ["acme/a", "acme/b"]
