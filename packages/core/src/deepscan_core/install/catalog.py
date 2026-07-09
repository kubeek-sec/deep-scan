"""Pinned tool catalog.

Every binary tool is pinned to an exact version and SHA-256 per platform.
The installer refuses to install anything that does not match its checksum.

To upgrade a tool: bump ``version`` (it is the single source of truth - the
artifact URLs and docker image expand ``{version}`` from it), refresh the
per-platform digests from the vendor's published checksum file (or by hashing
the downloaded artifact from two independent networks), and update the URL
template if the asset naming changed.
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field
from enum import Enum


class ToolKind(str, Enum):
    ARCHIVE = "archive"  # tar.gz / zip containing the binary
    ARCHIVE_DIR = "archive_dir"  # zip extracted as a whole tree (e.g. CodeQL)
    BINARY = "binary"  # raw executable
    DOCKER = "docker"  # docker image, installed via `docker pull`
    SYSTEM = "system"  # OS package (e.g. ClamAV) - found on PATH, installed via the system package manager
    UV = "uv"  # Python tool installed/run via uv (`uv tool install` / `uvx`)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    kind: ToolKind
    # platform key ("linux-amd64", "darwin-arm64") -> (download URL, sha256)
    artifacts: dict[str, tuple[str, str]] = field(default_factory=dict)
    archive_member: str | None = None  # binary path inside the archive (ARCHIVE)
    launcher: str | None = None  # executable path inside the extracted tree (ARCHIVE_DIR)
    max_bytes: int | None = None  # per-tool download size cap (bytes); None = default
    # Extra components fetched after install by running the launcher (CodeQL
    # query packs: ``<launcher> pack download <pack>...``). Best-effort.
    query_packs: tuple[str, ...] = ()
    docker_image: str | None = None
    # SYSTEM / UV tools: the program to run (and look up on PATH).
    executable: str | None = None
    system_package: str | None = None  # SYSTEM: OS package name to install
    uv_package: str | None = None  # UV: PyPI package name (run via uv / uvx)
    homepage: str = ""


def platform_key() -> str:
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(
        machine, machine
    )
    system = "darwin" if sys.platform == "darwin" else "linux"
    return f"{system}-{arch}"


_GH = "https://github.com"


def _tool(
    name: str,
    version: str,
    kind: ToolKind,
    *,
    artifacts: dict[str, tuple[str, str]] | None = None,
    docker_image: str | None = None,
    **kwargs,
) -> ToolSpec:
    """Build a :class:`ToolSpec`, expanding ``{version}`` (plus ``{gh}`` for the
    GitHub base and ``{name}``) in each artifact URL and the docker image.

    This keeps ``version`` the single source of truth: bumping it updates every
    URL automatically, so there is only one place to edit per tool.
    """
    def _fmt(text: str) -> str:
        return text.format(gh=_GH, version=version, name=name)

    resolved = {
        plat: (_fmt(url), sha) for plat, (url, sha) in (artifacts or {}).items()
    }
    return ToolSpec(
        name=name,
        version=version,
        kind=kind,
        artifacts=resolved,
        docker_image=_fmt(docker_image) if docker_image else None,
        **kwargs,
    )


TOOLS: dict[str, ToolSpec] = {
    "trivy": _tool(
        "trivy",
        "0.71.0",
        ToolKind.ARCHIVE,
        archive_member="trivy",
        homepage="https://github.com/aquasecurity/trivy",
        artifacts={
            "linux-amd64": (
                "{gh}/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-64bit.tar.gz",
                "30a3d22b23f88c233f1658f562fb477cae3b3e8b4761109d515b7698daf85814",
            ),
            "darwin-arm64": (
                "{gh}/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_macOS-ARM64.tar.gz",
                "95d4e896b120816edd0995a2df8adca26a8621b7bf62036a89b1d54a7b718a74",
            ),
        },
    ),
    "osv-scanner": _tool(
        "osv-scanner",
        "2.3.8",
        ToolKind.BINARY,
        homepage="https://github.com/google/osv-scanner",
        artifacts={
            "linux-amd64": (
                "{gh}/google/osv-scanner/releases/download/v{version}/osv-scanner_linux_amd64",
                "bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc",
            ),
            "darwin-arm64": (
                "{gh}/google/osv-scanner/releases/download/v{version}/osv-scanner_darwin_arm64",
                "a8cd6507b06239f463a7642430cfd2d154882f150f6e30cdc0653e28dfc34216",
            ),
        },
    ),
    "gitleaks": _tool(
        "gitleaks",
        "8.30.1",
        ToolKind.ARCHIVE,
        archive_member="gitleaks",
        homepage="https://github.com/gitleaks/gitleaks",
        artifacts={
            "linux-amd64": (
                "{gh}/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_linux_x64.tar.gz",
                "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
            ),
            "darwin-arm64": (
                "{gh}/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_darwin_arm64.tar.gz",
                "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
            ),
        },
    ),
    "trufflehog": _tool(
        "trufflehog",
        "3.95.5",
        ToolKind.ARCHIVE,
        archive_member="trufflehog",
        homepage="https://github.com/trufflesecurity/trufflehog",
        artifacts={
            "linux-amd64": (
                "{gh}/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_linux_amd64.tar.gz",
                "8d151a19465973bec226be5992a2a11b053f4ab92c77861f642089892ae9aa58",
            ),
            "darwin-arm64": (
                "{gh}/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_darwin_arm64.tar.gz",
                "0a08b46f63d48ccb894689b68b5e7b91ac5efa09b9684a3457d388456887c213",
            ),
        },
    ),
    "opengrep": _tool(
        "opengrep",
        "1.22.0",
        ToolKind.BINARY,
        homepage="https://github.com/opengrep/opengrep",
        artifacts={
            "linux-amd64": (
                "{gh}/opengrep/opengrep/releases/download/v{version}/opengrep_manylinux_x86",
                "45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319",
            ),
            "darwin-arm64": (
                "{gh}/opengrep/opengrep/releases/download/v{version}/opengrep_osx_arm64",
                "6105ab78eca041fcb9f83055939088ba8f96a6cb66683ceced39652938b217ce",
            ),
        },
    ),
    "nuclei": _tool(
        "nuclei",
        "3.9.0",
        ToolKind.ARCHIVE,
        archive_member="nuclei",
        homepage="https://github.com/projectdiscovery/nuclei",
        artifacts={
            "linux-amd64": (
                "{gh}/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_linux_amd64.zip",
                "05357e07886d9670e9c54325ec8afd362d03610c87e2aa1455886ad3f7b58519",
            ),
            "darwin-arm64": (
                "{gh}/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_macOS_arm64.zip",
                "62f6bd1d554688e4c0fdd96f6dbbd7ec46fe1b4506a361fc01ef525425b0f060",
            ),
        },
    ),
    "zaproxy": _tool(
        "zaproxy",
        "stable",
        ToolKind.DOCKER,
        docker_image="ghcr.io/zaproxy/zaproxy:{version}",
        homepage="https://www.zaproxy.org",
    ),
    "nosey_parker": _tool(
        "nosey_parker",
        "0.24.0",
        ToolKind.ARCHIVE,
        archive_member="bin/noseyparker",
        homepage="https://github.com/praetorian-inc/noseyparker",
        artifacts={
            "linux-amd64": (
                "{gh}/praetorian-inc/noseyparker/releases/download/v{version}/noseyparker-v{version}-x86_64-unknown-linux-gnu.tar.gz",
                "1bd04ea06ce886a7cd1995a814c5570be01b019adacf27fd158cbdfb01da1f3c",
            ),
            "darwin-arm64": (
                "{gh}/praetorian-inc/noseyparker/releases/download/v{version}/noseyparker-v{version}-aarch64-apple-darwin.tar.gz",
                "b19f983d586a738f127bc8c53ef1331055010db4926ac1789791f717fcc107b7",
            ),
        },
    ),
    "titus": _tool(
        "titus",
        "1.2.1",
        ToolKind.BINARY,
        homepage="https://github.com/praetorian-inc/titus",
        artifacts={
            "linux-amd64": (
                "{gh}/praetorian-inc/titus/releases/download/v{version}/titus-linux-amd64",
                "2a9ae9751e29dab03158ddee964cdf355504b5478673156e9f52a17cebda5d97",
            ),
            "darwin-arm64": (
                "{gh}/praetorian-inc/titus/releases/download/v{version}/titus-darwin-arm64",
                "2a20b23396be4c9b7ca496c691d0318118721037f07ac00788c9e2a10e26f148",
            ),
        },
    ),
    "betterleaks": _tool(
        "betterleaks",
        "1.4.1",
        ToolKind.ARCHIVE,
        archive_member="betterleaks",
        homepage="https://github.com/betterleaks/betterleaks",
        artifacts={
            "linux-amd64": (
                "{gh}/betterleaks/betterleaks/releases/download/v{version}/betterleaks_{version}_linux_x64.tar.gz",
                "2635ff988d9194cd3070155138589081a54a3438d79ca9b83268addd2fd844cc",
            ),
            "darwin-arm64": (
                "{gh}/betterleaks/betterleaks/releases/download/v{version}/betterleaks_{version}_darwin_arm64.tar.gz",
                "0656a339d4a99fc3a037d0d31b70f3b3f4fec1e38459bf837e204540043c9b76",
            ),
        },
    ),
    "kingfisher": _tool(
        "kingfisher",
        "1.54.0",
        ToolKind.ARCHIVE,
        archive_member="kingfisher",
        homepage="https://github.com/mongodb/kingfisher",
        artifacts={
            "linux-amd64": (
                "{gh}/mongodb/kingfisher/releases/download/v{version}/kingfisher-linux-x64.tgz",
                "f5515a75e5b18923131bc4353b278beadf13e3c0861b074105180f067fb0a290",
            ),
            "darwin-arm64": (
                "{gh}/mongodb/kingfisher/releases/download/v{version}/kingfisher-darwin-arm64.tgz",
                "26756f366f5b8462098ebda2efa67898cabc5fe59dc63d43c359b82b7f1fff26",
            ),
        },
    ),
    "plumber": _tool(
        "plumber",
        "0.3.58",
        ToolKind.BINARY,
        homepage="https://github.com/getplumber/plumber",
        artifacts={
            "linux-amd64": (
                "{gh}/getplumber/plumber/releases/download/v{version}/plumber-linux-amd64",
                "a191e3676a42ff44b31379eb9864e1ed3e36c927c8dc3825614f89ff6d547e93",
            ),
            "darwin-arm64": (
                "{gh}/getplumber/plumber/releases/download/v{version}/plumber-darwin-arm64",
                "c5da54f7b6182ef848dbab3aefbdbcbaf87e814882ff676205b21e00a5f0fb6a",
            ),
        },
    ),
    # CodeQL CLI bundle: a whole directory tree (launcher + extractors + query
    # packs), extracted as-is. Large (≈0.5–1.1 GB) → a raised per-tool size cap.
    "codeql": _tool(
        "codeql",
        "2.25.6",
        ToolKind.ARCHIVE_DIR,
        launcher="codeql/codeql",
        max_bytes=1300 * 1024 * 1024,
        # The CLI bundle ships no query packs; pre-download the standard security
        # packs so analysis works out of the box (cached under ~/.codeql/packages).
        query_packs=(
            "codeql/python-queries", "codeql/javascript-queries", "codeql/java-queries",
            "codeql/csharp-queries", "codeql/go-queries", "codeql/ruby-queries",
            "codeql/cpp-queries",
        ),
        homepage="https://github.com/github/codeql-cli-binaries",
        artifacts={
            "linux-amd64": (
                "{gh}/github/codeql-cli-binaries/releases/download/v{version}/codeql-linux64.zip",
                "d7108fe3ab439267f2dbadd5462096aa190c6258e06d90004faef04d65bf4281",
            ),
            "darwin-arm64": (
                "{gh}/github/codeql-cli-binaries/releases/download/v{version}/codeql-osx64.zip",
                "e3c521e6d394aed395e9b314de075d8854a3bdb560453fc947cf167623bf869d",
            ),
        },
    ),
    # ClamAV: an OS package (not a single pinned binary). Found on PATH as
    # ``clamscan``; installed via the system package manager (with sudo when
    # needed). Needs a virus DB - ``freshclam`` is run best-effort after install.
    "clamav": _tool(
        "clamav",
        "system",
        ToolKind.SYSTEM,
        executable="clamscan",
        system_package="clamav",
        homepage="https://www.clamav.net",
    ),
    # Cisco AI Defense Skill Scanner: a Python tool installed/run via uv. Scans
    # AI agent skills (prompt injection, data exfiltration, malicious code).
    "cisco-ai-skill-scanner": _tool(
        "cisco-ai-skill-scanner",
        "2.0.11",
        ToolKind.UV,
        executable="skill-scanner",
        uv_package="cisco-ai-skill-scanner",
        homepage="https://github.com/cisco-ai-defense/skill-scanner",
    ),
    # Checkov: IaC / config misconfiguration scanner (Bridgecrew). A Python tool
    # installed/run via uv.
    "checkov": _tool(
        "checkov",
        "3.3.1",
        ToolKind.UV,
        executable="checkov",
        uv_package="checkov",
        homepage="https://github.com/bridgecrewio/checkov",
    ),
}
