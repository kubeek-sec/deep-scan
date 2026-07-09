"""CI/CD pipeline template generator for the web wizard.

The web app's **CI templates** tab walks the user through five steps - platform,
capabilities (+ per-tool toggles), report formats, the severity gate and whether
to *fail* or *warn* - and POSTs that selection here. We render a
ready-to-commit pipeline file that runs the Deep Scan CLI **inside this project's
Docker image** (built from ``deploy/docker/Dockerfile`` and pushed to the user's
registry), invoked through ``uv run … deepscan scan`` with the flags the user
picked.

Single source of truth: the capability → tool list is derived from the live
scanner :mod:`registry`, so the wizard can never offer a scanner the CLI can't
run, and new scanners show up automatically.

Two execution shapes, chosen per platform for templates that work out of the box:

* **container-native** (GitLab, Bitbucket): the job already runs *in* the image,
  so the step is just ``uv run … deepscan scan .``.
* **docker run** (GitHub, Gitea, Azure, Jenkins, TeamCity): a generic runner
  pulls the image and runs the CLI inside it. We map the runner UID
  (``--user "$(id -u):$(id -g)"``) so the mounted workspace stays writable, point
  ``HOME`` at ``/tmp`` (writable scratch for uv/scanner caches), and set
  ``DEEPSCAN_WAIT_FOR_DB=false`` so the image entrypoint doesn't block waiting for
  a Postgres that a CI scan doesn't need.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from deepscan_core import registry
from deepscan_core.models import Mode, Severity
from deepscan_core.reporting import ALL_FORMATS, report_filename

# Default image tag - matches docker-compose; override in the wizard's advanced
# options to point at wherever the user pushes ``deploy/docker/Dockerfile``.
DEFAULT_IMAGE = "kubeek-sec/deepscan:latest"
# Trivy's own image, used for the SBOM step on docker-run platforms (the project
# image bundles Trivy too, used for the native-platform SBOM step). Pin matches
# the trivy server in docker-compose.
SBOM_TRIVY_IMAGE = "aquasec/trivy:0.71.0"
# Where the workspace venv lives inside the image (Dockerfile WORKDIR /app).
PROJECT_DIR = "/app"
# CLI invocation prefix: run the installed ``deepscan`` console script through uv,
# using the image's frozen project env without trying to re-sync it (offline-safe).
_CLI_PREFIX = ("uv", "run", "--project", PROJECT_DIR, "--no-sync", "deepscan")

DEFAULT_REPORTS_DIR = "deepscan-reports"
DEFAULT_TARGET = "."
DEFAULT_FORMATS = ("sarif", "html")
DEFAULT_FAIL_ON = "high"

_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REL_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

# Ordered capabilities the wizard offers. Each (except the synthetic ``sbom``)
# maps 1:1 to a scanner Family; its tool list is pulled from the registry.
_CAPABILITY_META: dict[str, tuple[str, str]] = {
    "secret": ("Secret detection", "Hardcoded secrets, API keys & tokens."),
    "sca": ("Dependency vulnerabilities (SCA)", "Known CVEs in your dependencies."),
    "sbom": ("SBOM generation", "CycloneDX software bill of materials (via Trivy)."),
    "sast": ("Static analysis (SAST)", "Source-code vulnerability patterns & dataflow."),
    "iac": ("IaC misconfiguration", "Terraform / Kubernetes / Dockerfile / Helm misconfig."),
    "license": ("License compliance", "Dependency license policy checks."),
    "pipeline": ("CI/CD pipeline security", "Action/image pinning, branch protection, pipeline secrets."),
    "malware": ("Malware & threat signatures", "Virus signatures, YARA & threat/prompt-injection patterns."),
    "analysis": ("Code-graph analysis", "Taint / reachability over the code graph (no AI)."),
    "ai": ("AI triage (opt-in)", "LLM prioritization over other scanners' findings; needs a model."),
}
_CAPABILITY_ORDER = list(_CAPABILITY_META.keys())


class PipelineError(ValueError):
    """Invalid wizard selection - surfaced to the client as a 400."""


# Each platform: how the generated file is named and which renderer builds it.
_PLATFORMS: dict[str, dict[str, str]] = {
    "github": {"label": "GitHub Actions", "filename": ".github/workflows/deepscan.yml", "language": "yaml"},
    "gitea": {"label": "Gitea Actions", "filename": ".gitea/workflows/deepscan.yml", "language": "yaml"},
    "gitlab": {"label": "GitLab CI", "filename": ".gitlab-ci.yml", "language": "yaml"},
    "bitbucket": {"label": "Bitbucket Pipelines", "filename": "bitbucket-pipelines.yml", "language": "yaml"},
    "azure": {"label": "Azure Pipelines", "filename": "azure-pipelines.yml", "language": "yaml"},
    "jenkins": {"label": "Jenkins", "filename": "Jenkinsfile", "language": "groovy"},
    "teamcity": {"label": "TeamCity (Kotlin DSL)", "filename": ".teamcity/settings.kts", "language": "kotlin"},
}


# --------------------------------------------------------------------------- #
# Catalog exposed to the wizard
# --------------------------------------------------------------------------- #


def _family_scanners(family_value: str) -> list[registry.Scanner]:
    """Static-mode scanners in a family, sorted by name (CI scans a repo, not a
    live URL, so dynamic/DAST scanners are excluded)."""
    out = [
        s
        for s in registry.REGISTRY.values()
        if s.family.value == family_value and s.mode == Mode.STATIC
    ]
    return sorted(out, key=lambda s: s.name)


def _capabilities() -> list[dict]:
    caps: list[dict] = []
    for key in _CAPABILITY_ORDER:
        label, desc = _CAPABILITY_META[key]
        if key == "sbom":
            caps.append(
                {
                    "key": "sbom",
                    "label": label,
                    "description": desc,
                    "family": None,
                    "tools": [
                        {
                            "name": "trivy",
                            "description": "CycloneDX SBOM of OS & language dependencies.",
                            "tool": "trivy",
                            "default": True,
                            "needs_tool": True,
                        }
                    ],
                }
            )
            continue
        scanners = _family_scanners(key)
        if not scanners:
            continue
        caps.append(
            {
                "key": key,
                "label": label,
                "description": desc,
                "family": key,
                "tools": [
                    {
                        "name": s.name,
                        "description": s.description,
                        "tool": s.tool or "",
                        "default": s.enabled_by_default,
                        "needs_tool": bool(s.tool),
                    }
                    for s in scanners
                ],
            }
        )
    return caps


def options() -> dict:
    """Everything the wizard needs to render its steps."""
    return {
        "image": DEFAULT_IMAGE,
        "defaults": {
            "target": DEFAULT_TARGET,
            "reports_dir": DEFAULT_REPORTS_DIR,
            "formats": list(DEFAULT_FORMATS),
            "fail_on": DEFAULT_FAIL_ON,
            "gate": "fail",
        },
        "platforms": [{"key": k, **v} for k, v in _PLATFORMS.items()],
        "capabilities": _capabilities(),
        "formats": list(ALL_FORMATS),
        "severities": [s.value for s in Severity],
        "gates": ["fail", "warn"],
    }


# --------------------------------------------------------------------------- #
# Plan: a validated, normalized selection
# --------------------------------------------------------------------------- #


@dataclass
class _Plan:
    platform: str
    image: str
    target: str
    reports_dir: str
    config_dir: str | None
    env: dict[str, str]
    families: list[str]
    scanners: list[str]
    use_families: bool
    has_scan: bool
    sbom: bool
    formats: list[str]
    fail_on: str | None
    warn: bool = field(default=False)


def _safe_rel(value: str | None, default: str, field_name: str) -> str:
    raw = (value or "").strip() or default
    raw = raw.strip("/") or "."
    if raw != "." and (not _REL_PATH_RE.match(raw) or ".." in raw.split("/")):
        raise PipelineError(
            f"Invalid {field_name} {value!r}: must be a relative path inside the repo."
        )
    return raw


def _resolve_capabilities(
    capabilities: list[dict],
) -> tuple[list[str], list[str], bool, bool, bool]:
    """Validate the per-capability tool selections and decide whether the scan
    can use ``--family`` flags (every selected family is *fully* selected) or must
    enumerate ``--scanner`` flags (any partial selection - the CLI does not let
    ``--family`` and ``--scanner`` mix in one run)."""
    known: dict[str, set[str]] = {
        key: {s.name for s in _family_scanners(key)}
        for key in _CAPABILITY_ORDER
        if key != "sbom"
    }
    seen_keys: set[str] = set()
    family_full: dict[str, bool] = {}
    chosen: list[str] = []
    sbom = False
    for cap in capabilities:
        key = (cap.get("key") or "").strip()
        if key in seen_keys:
            raise PipelineError(f"Duplicate capability {key!r}.")
        seen_keys.add(key)
        if key == "sbom":
            sbom = True
            continue
        if key not in known:
            raise PipelineError(
                f"Unknown capability {key!r}. Available: {', '.join(['sbom', *known])}"
            )
        available = known[key]
        if not available:
            continue
        selected = cap.get("scanners")
        names = (
            list(available)
            if not selected
            else [str(n).strip() for n in selected if str(n).strip()]
        )
        unknown = [n for n in names if n not in available]
        if unknown:
            raise PipelineError(
                f"Scanner(s) {', '.join(unknown)} are not part of the {key!r} capability."
            )
        if not names:
            continue
        chosen.extend(names)
        family_full[key] = set(names) == available

    families = list(family_full.keys())
    scanners = sorted(set(chosen))
    use_families = bool(family_full) and all(family_full.values())
    has_scan = bool(family_full)
    if not has_scan and not sbom:
        raise PipelineError("Select at least one capability to scan for.")
    return families, scanners, use_families, has_scan, sbom


def _build_plan(
    *,
    platform: str,
    capabilities: list[dict] | None,
    formats: list[str] | None,
    fail_on: str | None,
    gate: str,
    image: str | None,
    target: str | None,
    reports_dir: str | None,
    config_dir: str | None,
    env: dict[str, str] | None,
) -> _Plan:
    platform = (platform or "").strip().lower()
    if platform not in _PLATFORMS:
        raise PipelineError(
            f"Unknown platform {platform!r}. Available: {', '.join(_PLATFORMS)}"
        )

    formats = [str(f).strip().lower() for f in (formats or list(DEFAULT_FORMATS)) if str(f).strip()]
    if not formats:
        raise PipelineError("Select at least one report format.")
    unknown_fmt = [f for f in formats if f not in ALL_FORMATS]
    if unknown_fmt:
        raise PipelineError(
            f"Unknown report format(s) {', '.join(unknown_fmt)}. "
            f"Available: {', '.join(ALL_FORMATS)}"
        )
    # Preserve the canonical order, drop duplicates.
    formats = [f for f in ALL_FORMATS if f in set(formats)]

    gate = (gate or "fail").strip().lower()
    if gate not in ("fail", "warn"):
        raise PipelineError("Gate must be 'fail' or 'warn'.")

    fail_on_value: str | None = None
    if fail_on and str(fail_on).strip():
        try:
            fail_on_value = Severity(str(fail_on).strip().lower()).value
        except ValueError:
            valid = ", ".join(s.value for s in Severity)
            raise PipelineError(
                f"Unknown severity {fail_on!r}. Available: {valid}"
            ) from None

    clean_env: dict[str, str] = {}
    for raw_key, raw_val in (env or {}).items():
        key = str(raw_key).strip()
        if not key:
            continue
        if not _ENV_KEY_RE.match(key):
            raise PipelineError(f"Invalid environment variable name {raw_key!r}.")
        clean_env[key] = "" if raw_val is None else str(raw_val)

    families, scanners, use_families, has_scan, sbom = _resolve_capabilities(
        capabilities or []
    )

    return _Plan(
        platform=platform,
        image=(image or "").strip() or DEFAULT_IMAGE,
        target=_safe_rel(target, DEFAULT_TARGET, "target"),
        reports_dir=_safe_rel(reports_dir, DEFAULT_REPORTS_DIR, "reports directory"),
        config_dir=(
            _safe_rel(config_dir, ".", "rules directory")
            if config_dir and config_dir.strip()
            else None
        ),
        env=clean_env,
        families=families,
        scanners=scanners,
        use_families=use_families,
        has_scan=has_scan,
        sbom=sbom,
        formats=formats,
        fail_on=fail_on_value,
        warn=gate == "warn",
    )


# --------------------------------------------------------------------------- #
# Command building
# --------------------------------------------------------------------------- #


def _scan_argv(plan: _Plan) -> list[str]:
    argv = [*_CLI_PREFIX, "scan", plan.target]
    if plan.use_families:
        for fam in plan.families:
            argv += ["--family", fam]
    else:
        for name in plan.scanners:
            argv += ["--scanner", name]
    for fmt in plan.formats:
        argv += ["--format", fmt]
    if plan.fail_on:
        argv += ["--fail-on", plan.fail_on]
    argv += ["--out", plan.reports_dir]
    return argv


def _scan_command(plan: _Plan) -> str:
    return " ".join(_scan_argv(plan))


def _e_flag(key: str, value: str) -> str:
    return f'-e "{key}={value}"' if value != "" else f"-e {key}"


def _docker_run_block(plan: _Plan, host_var: str, *, suffix: str = "") -> str:
    """A multi-line ``docker run`` that scans the workspace with the project image."""
    parts = [
        "docker run",
        "--rm",
        '--user "$(id -u):$(id -g)"',
        "-e DEEPSCAN_WAIT_FOR_DB=false",
        "-e HOME=/tmp",
    ]
    for key, value in plan.env.items():
        parts.append(_e_flag(key, value))
    if plan.config_dir:
        parts.append(f"-e DEEPSCAN_CONFIG_DIR=/src/{plan.config_dir}")
    parts += [f'-v "{host_var}:/src"', "-w /src", plan.image, _scan_command(plan) + suffix]
    return " \\\n  ".join(parts)


def _sbom_docker_block(plan: _Plan, host_var: str, *, suffix: str = "") -> str:
    out = f"{plan.reports_dir}/sbom.cdx.json"
    parts = [
        "docker run",
        "--rm",
        '--user "$(id -u):$(id -g)"',
        f'-v "{host_var}:/src"',
        "-w /src",
        SBOM_TRIVY_IMAGE,
        f"fs --quiet --format cyclonedx --output {out} ." + suffix,
    ]
    return " \\\n  ".join(parts)


def _sbom_native_lines(plan: _Plan, *, suffix: str = "") -> list[str]:
    """Native-platform SBOM via the image's bundled Trivy (resolved through the
    installer's ``tool_path`` since it lives outside ``PATH``)."""
    out = f"{plan.reports_dir}/sbom.cdx.json"
    return [
        "TRIVY=$(python -c \"from deepscan_core.install import tool_path; "
        "print(tool_path('trivy') or '')\")",
        f'test -n "$TRIVY" && "$TRIVY" fs --quiet --format cyclonedx --output {out} . '
        f'|| echo "SBOM step skipped - trivy not bundled in image"' + suffix,
    ]


def _native_scan_lines(plan: _Plan, *, suffix: str = "") -> list[str]:
    lines = []
    if plan.has_scan:
        lines.append(_scan_command(plan) + suffix)
    if plan.sbom:
        lines += _sbom_native_lines(plan)
    return lines


def _native_env(plan: _Plan) -> dict[str, str]:
    """Env vars to declare in a container-native job. Empty-value entries are
    dropped: in a native job the CI's own variables are already in the
    environment, so only explicit literal values need declaring."""
    env = {"DEEPSCAN_WAIT_FOR_DB": "false"}
    env.update({k: v for k, v in plan.env.items() if v != ""})
    if plan.config_dir:
        env["DEEPSCAN_CONFIG_DIR"] = plan.config_dir
    return env


def _passthrough_keys(plan: _Plan) -> list[str]:
    """Env keys with no explicit value - passed through from the CI's secrets/vars
    into the container (``docker run -e KEY``)."""
    return [k for k, v in plan.env.items() if v == ""]


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


def _yaml_dq(value: str) -> str:
    """A YAML double-quoted scalar. Robust for shell command strings embedded as
    sequence items: it tolerates leading ``[``, mid-string ``: `` and ``"`` that
    would otherwise break a plain scalar, while leaving shell metacharacters
    (``$``, ``()``, ``&&``) for the shell to interpret."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _header(plan: _Plan, comment: str) -> list[str]:
    return [
        f"{comment} Generated by Deep Scan - CI template wizard.",
        f"{comment} Runs the Deep Scan CLI from the project image ({plan.image}).",
        f"{comment} Reports are written to ./{plan.reports_dir}/ and kept as build artifacts.",
        f"{comment} Pass CI secrets/variables to the scan via the env block (e.g. ANTHROPIC_API_KEY).",
    ]


def _has_junit(plan: _Plan) -> bool:
    # JUnit report wiring only makes sense when a scan actually writes one.
    return plan.has_scan and "junit" in plan.formats


def _sarif_file(plan: _Plan) -> str:
    return f"{plan.reports_dir}/{report_filename('sarif')}"


def _junit_file(plan: _Plan) -> str:
    return f"{plan.reports_dir}/{report_filename('junit')}"


# --------------------------------------------------------------------------- #
# Per-platform renderers
# --------------------------------------------------------------------------- #


def _render_github(plan: _Plan, *, gitea: bool = False) -> str:
    lines = _header(plan, "#")
    lines.append("name: Deep Scan")
    lines += ["on:", "  push:", "    branches: [ main ]", "  pull_request:"]
    want_sarif = "sarif" in plan.formats and not gitea and plan.has_scan
    if want_sarif:
        lines += ["permissions:", "  contents: read", "  security-events: write"]
    lines += ["jobs:", "  deep-scan:", "    runs-on: ubuntu-latest", "    steps:"]
    lines.append("      - uses: actions/checkout@v4")
    if plan.has_scan:
        lines.append("      - name: Run Deep Scan")
        passthrough = _passthrough_keys(plan)
        if passthrough:
            lines.append("        env:")
            for key in passthrough:
                lines.append(f"          {key}: ${{{{ secrets.{key} }}}}")
        if plan.warn:
            lines.append("        continue-on-error: true")
        lines.append("        run: |")
        lines.append(_indent(_docker_run_block(plan, "$GITHUB_WORKSPACE"), 10))
    if plan.sbom:
        lines.append("      - name: Generate SBOM")
        lines.append("        run: |")
        lines.append(_indent(_sbom_docker_block(plan, "$GITHUB_WORKSPACE"), 10))
    lines += [
        "      - name: Upload Deep Scan reports",
        "        if: always()",
        "        uses: actions/upload-artifact@v4",
        "        with:",
        "          name: deepscan-reports",
        f"          path: {plan.reports_dir}",
    ]
    if want_sarif:
        lines += [
            "      - name: Upload SARIF to code scanning",
            "        if: always()",
            "        uses: github/codeql-action/upload-sarif@v3",
            "        with:",
            f"          sarif_file: {_sarif_file(plan)}",
        ]
    return "\n".join(lines) + "\n"


def _render_gitea(plan: _Plan) -> str:
    return _render_github(plan, gitea=True)


def _render_gitlab(plan: _Plan) -> str:
    lines = _header(plan, "#")
    lines += ["stages:", "  - security", "", "deep-scan:", "  stage: security"]
    lines.append(f"  image: {plan.image}")
    lines.append("  variables:")
    for key, value in _native_env(plan).items():
        lines.append(f"    {key}: {_yaml_dq(value)}")
    if plan.warn:
        lines.append("  allow_failure: true")
    lines.append("  script:")
    for line in _native_scan_lines(plan):
        lines.append(f"    - {_yaml_dq(line)}")
    lines += ["  artifacts:", "    when: always", "    paths:", f"      - {plan.reports_dir}/"]
    if _has_junit(plan):
        lines += ["    reports:", f"      junit: {_junit_file(plan)}"]
    return "\n".join(lines) + "\n"


def _render_bitbucket(plan: _Plan) -> str:
    lines = _header(plan, "#")
    lines.append(f"image: {plan.image}")
    lines += ["pipelines:", "  default:", "    - step:", "        name: Deep Scan"]
    lines.append("        script:")
    suffix = " || true" if plan.warn else ""
    env_lines = [f'export {key}="{value}"' for key, value in _native_env(plan).items()]
    for line in [*env_lines, *_native_scan_lines(plan, suffix=suffix)]:
        lines.append(f"          - {_yaml_dq(line)}")
    lines += ["        artifacts:", f"          - {plan.reports_dir}/**"]
    return "\n".join(lines) + "\n"


def _render_azure(plan: _Plan) -> str:
    lines = _header(plan, "#")
    lines += ["trigger:", "  - main", "", "pool:", "  vmImage: ubuntu-latest", "", "steps:"]
    if plan.has_scan:
        lines.append("  - script: |")
        lines.append(_indent(_docker_run_block(plan, "$(Build.SourcesDirectory)"), 6))
        lines.append("    displayName: Run Deep Scan")
        if plan.warn:
            lines.append("    continueOnError: true")
        passthrough = _passthrough_keys(plan)
        if passthrough:
            lines.append("    env:")
            for key in passthrough:
                lines.append(f"      {key}: $({key})")
    if plan.sbom:
        lines.append("  - script: |")
        lines.append(_indent(_sbom_docker_block(plan, "$(Build.SourcesDirectory)"), 6))
        lines.append("    displayName: Generate SBOM")
    lines += [
        "  - task: PublishBuildArtifacts@1",
        "    condition: always()",
        "    inputs:",
        f"      pathToPublish: {plan.reports_dir}",
        "      artifactName: deepscan-reports",
    ]
    if _has_junit(plan):
        lines += [
            "  - task: PublishTestResults@2",
            "    condition: always()",
            "    inputs:",
            "      testResultsFormat: JUnit",
            f"      testResultsFiles: {_junit_file(plan)}",
        ]
    return "\n".join(lines) + "\n"


def _render_jenkins(plan: _Plan) -> str:
    suffix = " || true" if plan.warn else ""
    lines = _header(plan, "//")
    lines += ["pipeline {", "  agent any", "  stages {"]
    if plan.has_scan:
        lines += ["    stage('Deep Scan') {", "      steps {", "        sh '''"]
        lines.append(_indent(_docker_run_block(plan, "$WORKSPACE", suffix=suffix), 10))
        lines += ["        '''", "      }", "    }"]
    if plan.sbom:
        lines += ["    stage('SBOM') {", "      steps {", "        sh '''"]
        lines.append(_indent(_sbom_docker_block(plan, "$WORKSPACE"), 10))
        lines += ["        '''", "      }", "    }"]
    lines += ["  }", "  post {", "    always {"]
    lines.append(
        f"      archiveArtifacts artifacts: '{plan.reports_dir}/**', allowEmptyArchive: true"
    )
    if _has_junit(plan):
        lines.append(
            f"      junit testResults: '{_junit_file(plan)}', allowEmptyResults: true"
        )
    lines += ["    }", "  }", "}"]
    return "\n".join(lines) + "\n"


def _render_teamcity(plan: _Plan) -> str:
    suffix = " || true" if plan.warn else ""
    lines = _header(plan, "//")
    lines += [
        "import jetbrains.buildServer.configs.kotlin.*",
        "import jetbrains.buildServer.configs.kotlin.buildSteps.script",
        "",
        'version = "2024.03"',
        "",
        "project {",
        "    buildType(DeepScan)",
        "}",
        "",
        "object DeepScan : BuildType({",
        '    name = "Deep Scan"',
        f'    artifactRules = "{plan.reports_dir} => {plan.reports_dir}"',
        "    steps {",
    ]
    if plan.has_scan:
        lines += ["        script {", '            name = "Run Deep Scan"', '            scriptContent = """']
        lines.append(_indent(_docker_run_block(plan, "%teamcity.build.checkoutDir%", suffix=suffix), 16))
        lines += ['            """.trimIndent()', "        }"]
    if plan.sbom:
        lines += ["        script {", '            name = "Generate SBOM"', '            scriptContent = """']
        lines.append(_indent(_sbom_docker_block(plan, "%teamcity.build.checkoutDir%"), 16))
        lines += ['            """.trimIndent()', "        }"]
    lines += ["    }", "})"]
    return "\n".join(lines) + "\n"


_RENDERERS = {
    "github": _render_github,
    "gitea": _render_gitea,
    "gitlab": _render_gitlab,
    "bitbucket": _render_bitbucket,
    "azure": _render_azure,
    "jenkins": _render_jenkins,
    "teamcity": _render_teamcity,
}


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def generate(
    *,
    platform: str,
    capabilities: list[dict] | None = None,
    formats: list[str] | None = None,
    fail_on: str | None = DEFAULT_FAIL_ON,
    gate: str = "fail",
    image: str | None = None,
    target: str | None = None,
    reports_dir: str | None = None,
    config_dir: str | None = None,
    env: dict[str, str] | None = None,
) -> dict:
    """Render a pipeline file from a validated wizard selection.

    Returns ``{platform, label, filename, language, content}``. Raises
    :class:`PipelineError` (a ``ValueError``) on any invalid input.
    """
    plan = _build_plan(
        platform=platform,
        capabilities=capabilities,
        formats=formats,
        fail_on=fail_on,
        gate=gate,
        image=image,
        target=target,
        reports_dir=reports_dir,
        config_dir=config_dir,
        env=env,
    )
    meta = _PLATFORMS[plan.platform]
    return {
        "platform": plan.platform,
        "label": meta["label"],
        "filename": meta["filename"],
        "language": meta["language"],
        "content": _RENDERERS[plan.platform](plan),
    }