"""CI/CD pipeline template generator (``deepscan_api.pipelines``).

Pure unit tests - no database or external tools. Exercises the wizard catalog,
per-platform rendering, the family-vs-scanner flag logic, the severity gate and
the request-level validation surfaced by the API route.
"""

from __future__ import annotations

import pytest

from deepscan_api import pipelines

ALL_PLATFORMS = ["github", "gitea", "gitlab", "bitbucket", "azure", "jenkins", "teamcity"]


def _gen(platform, **kw):
    kw.setdefault("capabilities", [{"key": "secret", "scanners": ["gitleaks"]}])
    kw.setdefault("formats", ["sarif"])
    return pipelines.generate(platform=platform, **kw)


# --------------------------------------------------------------------------- #
# options() catalog
# --------------------------------------------------------------------------- #


def test_options_exposes_full_catalog():
    opt = pipelines.options()
    assert opt["image"] == pipelines.DEFAULT_IMAGE
    assert [p["key"] for p in opt["platforms"]] == ALL_PLATFORMS
    for p in opt["platforms"]:
        assert p["filename"] and p["label"] and p["language"]
    # severities critical→info, gates, formats present
    assert opt["severities"][0] == "critical" and opt["severities"][-1] == "info"
    assert set(opt["gates"]) == {"fail", "warn"}
    assert "sarif" in opt["formats"] and "pdf" in opt["formats"]


def test_options_capabilities_derived_from_registry():
    caps = {c["key"]: c for c in pipelines.options()["capabilities"]}
    # capabilities the user named, plus the synthetic SBOM
    for key in ("secret", "sca", "sbom", "sast", "iac", "license", "pipeline"):
        assert key in caps, key
    # secret tools come straight from the registry (gitleaks et al.)
    secret_tools = {t["name"] for t in caps["secret"]["tools"]}
    assert {"gitleaks", "trufflehog"} <= secret_tools
    # SBOM is synthetic: no family, single Trivy tool
    assert caps["sbom"]["family"] is None
    assert [t["name"] for t in caps["sbom"]["tools"]] == ["trivy"]
    # tool metadata carries the install hint and default flag
    cisco = next(t for t in caps["sast"]["tools"] if t["name"] == "cisco-ai-skill-scanner")
    assert cisco["needs_tool"] is True


def test_options_excludes_dynamic_scanners():
    caps = {c["key"]: c for c in pipelines.options()["capabilities"]}
    # DAST scanners (nuclei/zap) need a live URL - never offered as a CI capability
    assert "dast" not in caps
    all_tools = {t["name"] for c in caps.values() for t in c["tools"]}
    assert "nuclei" not in all_tools and "zaproxy" not in all_tools


# --------------------------------------------------------------------------- #
# generation - every platform renders the right shape
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("platform", ALL_PLATFORMS)
def test_every_platform_generates(platform):
    out = _gen(platform)
    meta = {p["key"]: p for p in pipelines.options()["platforms"]}[platform]
    assert out["filename"] == meta["filename"]
    assert out["language"] == meta["language"]
    # always runs the CLI through uv inside the project image
    assert "uv run --project /app --no-sync deepscan scan" in out["content"]
    assert "--scanner gitleaks" in out["content"]
    assert "--format sarif" in out["content"]


@pytest.mark.parametrize("platform", ["github", "gitea", "gitlab", "bitbucket", "azure"])
def test_yaml_platforms_parse(platform):
    yaml = pytest.importorskip("yaml")
    out = _gen(
        platform,
        capabilities=[{"key": "secret", "scanners": ["gitleaks"]}, {"key": "sbom"}],
        formats=["sarif", "junit"],
        gate="warn",
        env={"WEIRD": 'a: b [c] "d"', "PASS_THROUGH": ""},
        config_dir=".deepscan/config",
    )
    yaml.safe_load(out["content"])  # raises on malformed YAML


def test_docker_run_platforms_handle_runner_environment():
    # docker-run platforms must skip the DB wait and keep the workspace writable
    out = _gen("github")["content"]
    assert "DEEPSCAN_WAIT_FOR_DB=false" in out
    assert '--user "$(id -u):$(id -g)"' in out
    assert "-v \"$GITHUB_WORKSPACE:/src\"" in out


def test_container_native_platforms_use_image_directly():
    out = _gen("gitlab")["content"]
    assert f"image: {pipelines.DEFAULT_IMAGE}" in out
    # native job already runs in the image - no nested docker run
    assert "docker run" not in out
    assert 'DEEPSCAN_WAIT_FOR_DB: "false"' in out


# --------------------------------------------------------------------------- #
# family vs scanner flag logic
# --------------------------------------------------------------------------- #


def test_full_family_selection_uses_family_flag():
    # empty scanner list == "all tools" → a single --family flag (future-proof)
    out = _gen("github", capabilities=[{"key": "secret", "scanners": []}])["content"]
    assert "--family secret" in out
    assert "--scanner" not in out


def test_partial_selection_enumerates_scanners():
    out = _gen(
        "github",
        capabilities=[{"key": "secret", "scanners": ["gitleaks", "trufflehog"]}],
    )["content"]
    # a partial family forces explicit --scanner flags, never --family
    assert "--scanner gitleaks" in out and "--scanner trufflehog" in out
    assert "--family" not in out


def test_mixed_full_and_partial_falls_back_to_scanners():
    # one full family + one partial → the whole run must enumerate scanners
    # (the CLI does not let --family and --scanner mix in one invocation)
    out = _gen(
        "github",
        capabilities=[
            {"key": "secret", "scanners": []},          # full
            {"key": "sast", "scanners": ["opengrep"]},  # partial
        ],
    )["content"]
    assert "--family" not in out
    assert "--scanner opengrep" in out
    assert "--scanner gitleaks" in out  # secret family enumerated too


# --------------------------------------------------------------------------- #
# gate, formats, sbom
# --------------------------------------------------------------------------- #


def test_fail_gate_sets_threshold_and_blocks():
    out = _gen("github", fail_on="high", gate="fail")["content"]
    assert "--fail-on high" in out
    assert "continue-on-error" not in out


def test_warn_gate_is_non_blocking_per_platform():
    assert "continue-on-error: true" in _gen("github", gate="warn")["content"]
    assert "allow_failure: true" in _gen("gitlab", gate="warn")["content"]
    assert "continueOnError: true" in _gen("azure", gate="warn")["content"]
    assert "|| true" in _gen("jenkins", gate="warn")["content"]


def test_formats_become_flags_and_report_wiring():
    out = _gen("gitlab", formats=["sarif", "junit", "html"])["content"]
    assert "--format sarif" in out and "--format junit" in out and "--format html" in out
    # JUnit wires into GitLab's native test report
    assert "junit: deepscan-reports/report.junit.xml" in out


def test_sarif_uploads_to_github_code_scanning():
    out = _gen("github", formats=["sarif"])["content"]
    assert "github/codeql-action/upload-sarif@v3" in out
    assert "security-events: write" in out
    # Gitea has no code-scanning upload
    assert "upload-sarif" not in _gen("gitea", formats=["sarif"])["content"]


def test_sbom_adds_a_step():
    out = _gen("github", capabilities=[{"key": "sbom"}], formats=["sarif"])["content"]
    assert "sbom.cdx.json" in out
    assert pipelines.SBOM_TRIVY_IMAGE in out


def test_sbom_only_skips_the_scan_step():
    out = _gen("github", capabilities=[{"key": "sbom"}], formats=["sarif"])["content"]
    assert "deepscan scan" not in out  # no scan, just the SBOM step
    assert "sbom.cdx.json" in out
    # no empty/invalid "Run Deep Scan" step, and no report wiring for reports that
    # would never be written
    assert "Run Deep Scan" not in out
    assert "upload-sarif" not in out


@pytest.mark.parametrize("platform", ["github", "gitea", "gitlab", "bitbucket", "azure"])
def test_sbom_only_is_valid_yaml(platform):
    yaml = pytest.importorskip("yaml")
    out = _gen(platform, capabilities=[{"key": "sbom"}], formats=["junit"])["content"]
    yaml.safe_load(out)


# --------------------------------------------------------------------------- #
# advanced options
# --------------------------------------------------------------------------- #


def test_custom_image_and_paths():
    out = _gen(
        "github",
        image="registry.kubeek.com/deepscan:1.2.3",
        target="services/api",
        reports_dir="security/out",
    )["content"]
    assert "registry.kubeek.com/deepscan:1.2.3" in out
    assert "deepscan scan services/api" in out
    assert "--out security/out" in out


def test_config_dir_mounted_as_rules():
    out = _gen("github", config_dir=".deepscan/config")["content"]
    assert "DEEPSCAN_CONFIG_DIR=/src/.deepscan/config" in out


def test_passthrough_secret_wired_into_github_env():
    out = _gen("github", env={"ANTHROPIC_API_KEY": ""})["content"]
    assert "ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}" in out
    assert "-e ANTHROPIC_API_KEY" in out


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def test_unknown_platform_rejected():
    with pytest.raises(pipelines.PipelineError):
        _gen("travis")


def test_unknown_scanner_rejected():
    with pytest.raises(pipelines.PipelineError):
        _gen("github", capabilities=[{"key": "secret", "scanners": ["nope"]}])


def test_scanner_from_wrong_family_rejected():
    with pytest.raises(pipelines.PipelineError):
        _gen("github", capabilities=[{"key": "secret", "scanners": ["opengrep"]}])


def test_empty_selection_rejected():
    with pytest.raises(pipelines.PipelineError):
        _gen("github", capabilities=[], formats=["sarif"])


def test_unknown_format_rejected():
    with pytest.raises(pipelines.PipelineError):
        _gen("github", formats=["docx"])


def test_bad_severity_rejected():
    with pytest.raises(pipelines.PipelineError):
        _gen("github", fail_on="catastrophic")


def test_path_traversal_rejected():
    with pytest.raises(pipelines.PipelineError):
        _gen("github", reports_dir="../../etc")


def test_bad_env_name_rejected():
    with pytest.raises(pipelines.PipelineError):
        _gen("github", env={"bad name": "x"})


# --------------------------------------------------------------------------- #
# API route (no DB needed for the pipeline endpoints)
# --------------------------------------------------------------------------- #


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from deepscan_api.main import create_app

    # No context manager: the pipeline endpoints never touch the job store, so we
    # skip the DB-bound lifespan startup.
    return TestClient(create_app())


def test_route_options(client):
    resp = client.get("/api/pipeline/options")
    assert resp.status_code == 200
    assert resp.json()["platforms"]


def test_route_generate(client):
    resp = client.post(
        "/api/pipeline/generate",
        json={
            "platform": "github",
            "capabilities": [{"key": "secret", "scanners": ["gitleaks"]}],
            "formats": ["sarif"],
            "fail_on": "high",
            "gate": "fail",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"] == ".github/workflows/deepscan.yml"
    assert "deepscan scan" in body["content"]


def test_route_bad_request_is_400(client):
    resp = client.post("/api/pipeline/generate", json={"platform": "nope"})
    assert resp.status_code == 400
