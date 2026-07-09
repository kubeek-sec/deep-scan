"""GitLab connector tests - HTTP is monkeypatched, no network is touched."""

from __future__ import annotations

import pytest

from deepscan_input_connector_base import ConnectorConfigError
from deepscan_input_connector_gitlab import GitLabConnector, _with_page


def _project(pid, path, **kw):
    base = {
        "id": pid,
        "name": path.split("/")[-1],
        "path_with_namespace": path,
        "http_url_to_repo": f"https://gitlab.com/{path}.git",
        "default_branch": "master",
        "archived": False,
        "visibility": "private",
    }
    base.update(kw)
    return base


def test_validate_config():
    c = GitLabConnector()
    with pytest.raises(ConnectorConfigError):
        c.validate_config({})
    with pytest.raises(ConnectorConfigError):
        c.validate_config({"group": "a", "user": "b"})
    c.validate_config({"group": "team/platform"})


def test_with_page_sets_page_param():
    out = _with_page("https://gitlab.com/api/v4/groups/x/projects?per_page=100", "3")
    assert "page=3" in out and "per_page=100" in out


def test_discover_paginates_and_filters(monkeypatch):
    c = GitLabConnector()
    pages = {
        "page1": ([_project(1, "team/api"), _project(2, "team/old", archived=True)], "PAGE2"),
        "page2": ([_project(3, "team/web")], None),
    }
    monkeypatch.setattr(
        GitLabConnector,
        "_get",
        lambda self, url, token: pages["page2"] if "PAGE2" in url else pages["page1"],
    )
    sources = list(c.discover({"group": "team"}))
    names = sorted(s.name for s in sources)
    assert names == ["team/api", "team/web"]  # archived excluded by default
    api = next(s for s in sources if s.name == "team/api")
    assert api.external_id == "1" and api.default_branch == "master"
    assert api.location == "https://gitlab.com/team/api.git"


def test_name_regex(monkeypatch):
    c = GitLabConnector()
    monkeypatch.setattr(
        GitLabConnector,
        "_get",
        lambda self, url, token: ([_project(1, "team/infra-a"), _project(2, "team/app")], None),
    )
    names = [s.name for s in c.discover({"group": "team", "name_regex": "^team/infra-"})]
    assert names == ["team/infra-a"]
