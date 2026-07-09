"""Direct git-URL connector tests - git plumbing is monkeypatched."""

from __future__ import annotations

from pathlib import Path

import pytest

import deepscan_input_connector_git as gitmod
from deepscan_input_connector_base import ConnectorConfigError
from deepscan_input_connector_git import GitConnector


def test_discover_single_url_no_token():
    c = GitConnector()
    sources = list(c.discover({"url": "https://github.com/michoo/flanby"}))
    assert len(sources) == 1
    s = sources[0]
    assert s.kind == "git"
    assert s.name == "michoo/flanby"
    assert s.location == "https://github.com/michoo/flanby"
    assert s.default_branch is None  # use remote default branch
    assert s.metadata["token_env"] is None  # anonymous is fine


def test_discover_multiple_with_branch():
    c = GitConnector()
    sources = list(
        c.discover(
            {"urls": ["https://github.com/michoo/b.git", "https://gitlab.com/michoo/d"], "branch": "main"}
        )
    )
    assert [(s.name, s.default_branch) for s in sources] == [
        ("michoo/b", "main"),
        ("michoo/d", "main"),
    ]


def test_validate_config_errors():
    c = GitConnector()
    for bad in ({}, {"url": "ftp://x/y"}, {"url": "https:///nopath"}):
        with pytest.raises(ConnectorConfigError):
            c.validate_config(bad)


def test_current_revision_and_materialize(monkeypatch):
    c = GitConnector()
    seen = {}

    def fake_ls(url, branch, *, token=None, username="x-access-token"):
        seen["ls"] = (url, branch, token, username)
        return "deadbeef"

    def fake_clone(url, dest, *, branch=None, token=None, username="x-access-token"):
        seen["clone"] = (url, branch, token, username)
        return dest

    monkeypatch.setattr(gitmod, "ls_remote_sha", fake_ls)
    monkeypatch.setattr(gitmod, "shallow_clone", fake_clone)
    monkeypatch.setenv("MY_PAT", "secret-token")

    cfg = {"url": "https://kubeek.com/info/o/r", "token_env": "MY_PAT", "auth_username": "oauth2"}
    src = next(iter(c.discover(cfg)))

    assert c.current_revision(src, cfg) == "deadbeef"
    assert seen["ls"] == ("https://kubeek.com/info/o/r", None, "secret-token", "oauth2")

    c.materialize(src, "deadbeef", Path("/tmp/dest"), cfg)
    assert seen["clone"] == ("https://kubeek.com/info/o/r", None, "secret-token", "oauth2")


def test_anonymous_when_token_env_missing(monkeypatch):
    c = GitConnector()
    captured = {}
    monkeypatch.setattr(
        gitmod, "ls_remote_sha",
        lambda url, branch, *, token=None, username="x-access-token": captured.setdefault("token", token) or "sha",
    )
    cfg = {"url": "https://github.com/michoo/flanby"}  # no token_env
    src = next(iter(c.discover(cfg)))
    c.current_revision(src, cfg)
    assert captured["token"] is None  # cloned/probed anonymously
