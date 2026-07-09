"""Unit tests for the connector contract, registry and shared helpers."""

from __future__ import annotations

import pytest

from deepscan_input_connector_base import (
    KIND_GIT,
    ConnectorConfigError,
    DiscoveredSource,
    available,
    directory_signature,
    get,
    token_from_env,
)
from deepscan_input_connector_base.git_support import authenticated_url


def test_registry_has_bundled_connectors():
    # Importing the kruncher package registers the three shipped connectors.
    import deepscan_kruncher.connectors  # noqa: F401

    assert {"github", "gitlab", "directory"} <= set(available())
    assert get("github").name == "github"


def test_unknown_connector_raises():
    with pytest.raises(ConnectorConfigError):
        get("does-not-exist")


def test_discovered_source_validates_kind():
    with pytest.raises(ConnectorConfigError):
        DiscoveredSource(external_id="x", kind="bogus", name="x", location="x")
    with pytest.raises(ConnectorConfigError):
        DiscoveredSource(external_id="", kind=KIND_GIT, name="x", location="x")


def test_token_from_env(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "  abc ")
    assert token_from_env("MY_TOKEN") == "abc"
    assert token_from_env(None) is None
    monkeypatch.setenv("EMPTY", "   ")
    assert token_from_env("EMPTY") is None


def test_authenticated_url_injects_and_redacts():
    url = authenticated_url("https://github.com/acme/repo.git", token="SECRET")
    assert url == "https://x-access-token:SECRET@github.com/acme/repo.git"
    assert authenticated_url("https://h/r.git", token=None) == "https://h/r.git"
    gl = authenticated_url("https://gitlab.com/g/p.git", token="T", username="oauth2")
    assert gl.startswith("https://oauth2:T@")


def test_directory_signature_changes_on_edit(tmp_path):
    (tmp_path / "a.py").write_text("print(1)")
    sig1 = directory_signature(tmp_path)
    sig2 = directory_signature(tmp_path)
    assert sig1 == sig2  # stable when nothing changes
    (tmp_path / "a.py").write_text("print(2)")  # same size, content change...
    (tmp_path / "b.py").write_text("x = 1")  # ...plus a new file
    assert directory_signature(tmp_path) != sig1


def test_directory_signature_ignores_vcs_dirs(tmp_path):
    (tmp_path / "keep.py").write_text("1")
    git = tmp_path / ".git"
    git.mkdir()
    before = directory_signature(tmp_path)
    (git / "HEAD").write_text("ref: refs/heads/main")
    assert directory_signature(tmp_path) == before  # .git churn is ignored
