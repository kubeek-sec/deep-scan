"""Secure tool installation.

Downloads pinned artifacts over HTTPS, verifies the SHA-256 against the
catalog before anything is extracted or executed, extracts only the expected
archive member (defeating zip-slip), and installs atomically.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..log import get_logger
from .catalog import TOOLS, ToolKind, ToolSpec, platform_key

_MAX_DOWNLOAD_BYTES = 600 * 1024 * 1024
_DOWNLOAD_TIMEOUT = 600
_USER_AGENT = "deepscan-installer/0.1"
_log = get_logger("install")


class InstallError(RuntimeError):
    pass


@dataclass
class ToolStatus:
    name: str
    version: str
    kind: str
    installed: bool
    path: str | None


def tool_dir(spec: ToolSpec) -> Path:
    return config.tools_dir() / spec.name / spec.version


def tool_path(name: str) -> Path | None:
    """Path of the installed binary/launcher, or None if missing / docker-based."""
    spec = TOOLS.get(name)
    if spec is None or spec.kind == ToolKind.DOCKER:
        return None
    if spec.kind in (ToolKind.SYSTEM, ToolKind.UV):
        # Resolved off PATH (SYSTEM: the OS binary; UV: the installed console
        # script). UV tools may also run via ``uvx`` even when not on PATH.
        found = shutil.which(spec.executable or spec.name)
        return Path(found) if found else None
    if spec.kind == ToolKind.ARCHIVE_DIR:
        candidate = tool_dir(spec) / (spec.launcher or spec.name)
    else:
        candidate = tool_dir(spec) / spec.name
    return candidate if candidate.is_file() else None


def is_installed(name: str) -> bool:
    spec = TOOLS.get(name)
    if spec is None:
        return False
    if spec.kind == ToolKind.DOCKER:
        return _docker_image_present(spec.docker_image or "")
    if spec.kind == ToolKind.SYSTEM:
        return shutil.which(spec.executable or spec.name) is not None
    if spec.kind == ToolKind.UV:
        return (
            shutil.which(spec.executable or spec.name) is not None
            or _uv_tool_installed(spec)
        )
    return tool_path(name) is not None


def status(name: str) -> ToolStatus:
    spec = TOOLS[name]
    path = tool_path(name)
    return ToolStatus(
        name=spec.name,
        version=spec.version,
        kind=spec.kind.value,
        installed=is_installed(name),
        path=str(path) if path else (spec.docker_image if spec.kind == ToolKind.DOCKER else None),
    )


def status_all() -> list[ToolStatus]:
    return [status(name) for name in sorted(TOOLS)]


def install(name: str, *, force: bool = False) -> ToolStatus:
    spec = TOOLS.get(name)
    if spec is None:
        raise InstallError(f"Unknown tool: {name!r}. Known: {', '.join(sorted(TOOLS))}")
    if spec.kind == ToolKind.DOCKER:
        _docker_pull(spec)
        return status(name)
    if not force and is_installed(name):
        return status(name)
    if spec.kind == ToolKind.SYSTEM:
        _install_system(spec)
        return status(name)
    if spec.kind == ToolKind.UV:
        _install_uv(spec)
        return status(name)

    key = platform_key()
    artifact = spec.artifacts.get(key)
    if artifact is None:
        raise InstallError(
            f"{spec.name} {spec.version} has no pinned artifact for platform {key}."
        )
    url, expected_sha256 = artifact
    if not url.startswith("https://"):
        raise InstallError(f"Refusing non-HTTPS download URL for {spec.name}: {url}")

    data = _download(url, spec.max_bytes)
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise InstallError(
            f"Checksum mismatch for {spec.name} {spec.version}: "
            f"expected {expected_sha256}, got {digest}. Aborting install."
        )

    # Directory-tree tools (e.g. CodeQL): extract the whole verified archive,
    # atomically swapped into place. zip-slip is guarded in _extract_tree.
    if spec.kind == ToolKind.ARCHIVE_DIR:
        _install_tree(spec, url, data)
        return status(name)

    binary = _extract_binary(spec, url, data)
    dest_dir = tool_dir(spec)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / spec.name
    # Atomic install: write to a temp file in the same directory, then rename.
    fd, tmp_name = tempfile.mkstemp(dir=dest_dir, prefix=".install-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(binary)
        os.chmod(tmp_name, 0o755)
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return status(name)


def install_all(names: list[str] | None = None, *, force: bool = False) -> list[ToolStatus]:
    """Install tools, best-effort (a failure is logged and skipped, never blocks
    the rest). When no explicit ``names`` are given, SYSTEM (OS package, needs
    root/apt) and UV (needs ``uv`` + heavier deps) tools are skipped - install
    those explicitly (``deepscan tools install clamav`` /
    ``... cisco-ai-skill-scanner``) since they have external prerequisites."""
    implicit = names is None
    results = []
    for name in names or sorted(TOOLS):
        spec = TOOLS.get(name)
        if implicit and spec is not None and spec.kind in (ToolKind.SYSTEM, ToolKind.UV):
            _log.info(
                "install all: skipping %s (kind=%s) - install it explicitly",
                name, spec.kind.value,
            )
            continue
        try:
            results.append(install(name, force=force))
        except InstallError as exc:
            _log.warning("install %s failed (continuing): %s", name, exc)
            results.append(status(name))
    return results


def _download(url: str, max_bytes: int | None = None) -> bytes:
    cap = max_bytes or _MAX_DOWNLOAD_BYTES
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_DOWNLOAD_TIMEOUT) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > cap:
                raise InstallError(f"Artifact too large ({length} bytes): {url}")
            data = response.read(cap + 1)
            if len(data) > cap:
                raise InstallError(f"Artifact exceeded size limit: {url}")
            return data
    except OSError as exc:
        raise InstallError(f"Download failed for {url}: {exc}") from exc


def _install_tree(spec: ToolSpec, url: str, data: bytes) -> None:
    """Extract a directory-tree tool into its versioned dir, atomically."""
    dest = tool_dir(spec)
    staging = dest.parent / f"{dest.name}.installing"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    _extract_tree(spec, url, data, staging)
    launcher = staging / (spec.launcher or "")
    if not spec.launcher or not launcher.is_file():
        shutil.rmtree(staging, ignore_errors=True)
        raise InstallError(f"Launcher {spec.launcher!r} not found after extracting {spec.name}.")
    os.chmod(launcher, os.stat(launcher).st_mode | 0o755)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    os.replace(staging, dest)
    _download_query_packs(spec, dest / spec.launcher)


def _download_query_packs(spec: ToolSpec, launcher: Path) -> None:
    """Best-effort: pre-fetch a tool's query packs (e.g. CodeQL's standard
    security packs) so analysis works offline. A failure is non-fatal - the
    packs can still be fetched at scan time (``analyze --download``)."""
    if not spec.query_packs:
        return
    _log.info("%s: downloading %d query pack(s)…", spec.name, len(spec.query_packs))
    try:
        result = subprocess.run(
            [str(launcher), "pack", "download", *spec.query_packs],
            capture_output=True, text=True, timeout=1800, check=False,
        )
        if result.returncode != 0:
            _log.warning(
                "%s: query-pack download failed (non-fatal; fetched at scan time): %s",
                spec.name, (result.stderr or result.stdout).strip()[-300:],
            )
    except (OSError, subprocess.SubprocessError) as exc:
        _log.warning("%s: query-pack download skipped (non-fatal): %s", spec.name, exc)


def _extract_tree(spec: ToolSpec, url: str, data: bytes, dest: Path) -> None:
    """Extract a whole zip into *dest*, blocking zip-slip and preserving the
    executable bits the archive records (CodeQL ships many executables)."""
    if not url.endswith(".zip"):
        raise InstallError(f"{spec.name}: directory-tree install only supports .zip ({url}).")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            target = (dest / info.filename).resolve()
            if target != root and not str(target).startswith(str(root) + os.sep):
                raise InstallError(f"Unsafe path in {spec.name} archive: {info.filename!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            mode = (info.external_attr >> 16) & 0o7777
            if mode:
                os.chmod(target, mode)


def _extract_binary(spec: ToolSpec, url: str, data: bytes) -> bytes:
    if spec.kind == ToolKind.BINARY:
        return data
    member = spec.archive_member or spec.name
    if url.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for info in archive.getmembers():
                if info.name.lstrip("./") == member:
                    if not info.isreg():
                        raise InstallError(
                            f"Archive member {member} in {spec.name} is not a regular file."
                        )
                    extracted = archive.extractfile(info)
                    if extracted is None:
                        break
                    return extracted.read()
        raise InstallError(f"Member {member!r} not found in archive for {spec.name}.")
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.filename.lstrip("./") == member and not info.is_dir():
                    return archive.read(info)
        raise InstallError(f"Member {member!r} not found in archive for {spec.name}.")
    raise InstallError(f"Unsupported archive format for {spec.name}: {url}")


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _docker_image_present(image: str) -> bool:
    if not image or not _docker_available():
        return False
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return result.returncode == 0


def _docker_pull(spec: ToolSpec) -> None:
    if not _docker_available():
        raise InstallError(f"{spec.name} needs Docker, which is not installed.")
    result = subprocess.run(
        ["docker", "pull", spec.docker_image or ""],
        capture_output=True,
        text=True,
        timeout=_DOWNLOAD_TIMEOUT,
        check=False,
    )
    if result.returncode != 0:
        raise InstallError(
            f"docker pull failed for {spec.docker_image}: {result.stderr.strip()[:500]}"
        )


# --------------------------------------------------------------------------- #
# SYSTEM tools (OS package managers) - e.g. ClamAV
# --------------------------------------------------------------------------- #

# manager -> the command(s) to install a package (some need a refresh first).
_PKG_MANAGERS: dict[str, "list[list[str]]"] = {
    "apt-get": [["apt-get", "update"], ["apt-get", "install", "-y"]],
    "dnf": [["dnf", "install", "-y"]],
    "yum": [["yum", "install", "-y"]],
    "zypper": [["zypper", "--non-interactive", "install"]],
    "pacman": [["pacman", "-Sy", "--noconfirm"]],
    "apk": [["apk", "add", "--no-cache"]],
    "brew": [["brew", "install"]],  # brew must never run as root
}


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0  # type: ignore[attr-defined]


def _root_cmd(cmd: list[str]) -> list[str]:
    """Prefix with sudo when not already root and sudo is available."""
    if _is_root() or shutil.which("sudo") is None:
        return cmd
    return ["sudo", *cmd]


def _system_package_manager() -> str | None:
    if sys.platform == "darwin":
        return "brew" if shutil.which("brew") else None
    for manager in ("apt-get", "dnf", "yum", "zypper", "pacman", "apk"):
        if shutil.which(manager):
            return manager
    return None


def _install_system(spec: ToolSpec) -> None:
    package = spec.system_package or spec.executable or spec.name
    executable = spec.executable or spec.name
    manager = _system_package_manager()
    if manager is None:
        raise InstallError(
            f"No supported system package manager found to install {spec.name!r}. "
            f"Install the {package!r} package for your OS manually."
        )
    for step in _PKG_MANAGERS[manager]:
        cmd = [*step, package] if step[-1] not in ("update",) else step
        cmd = cmd if manager == "brew" else _root_cmd(cmd)
        _log.info("%s: %s", spec.name, " ".join(cmd))
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_DOWNLOAD_TIMEOUT, check=False
        )
        if result.returncode != 0:
            raise InstallError(
                f"{spec.name}: {' '.join(cmd)} failed: "
                f"{(result.stderr or result.stdout).strip()[-500:]}"
            )
    if shutil.which(executable) is None:
        raise InstallError(
            f"{spec.name}: {executable!r} is still not on PATH after install."
        )
    if executable == "clamscan":
        _freshclam_best_effort()


def _freshclam_best_effort() -> None:
    """Fetch/refresh the ClamAV virus DB so ``clamscan`` is usable. Non-fatal."""
    freshclam = shutil.which("freshclam")
    if not freshclam:
        return
    try:
        subprocess.run(
            _root_cmd([freshclam]),
            capture_output=True,
            text=True,
            timeout=_DOWNLOAD_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _log.warning("freshclam (ClamAV DB update) skipped: %s", exc)


# --------------------------------------------------------------------------- #
# UV tools (Python packages run via uv / uvx) - e.g. cisco-ai-skill-scanner
# --------------------------------------------------------------------------- #


def _uv_tool_installed(spec: ToolSpec) -> bool:
    if shutil.which("uv") is None:
        return False
    package = (spec.uv_package or spec.name).lower()
    try:
        result = subprocess.run(
            ["uv", "tool", "list"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    return any(line.strip().lower().startswith(package) for line in result.stdout.splitlines())


def _install_uv(spec: ToolSpec) -> None:
    if shutil.which("uv") is None:
        raise InstallError(
            f"{spec.name} needs 'uv', which is not installed. "
            "See https://docs.astral.sh/uv/ to install it."
        )
    package = spec.uv_package or spec.name
    cmd = ["uv", "tool", "install", f"{package}=={spec.version}"]
    _log.info("%s: %s", spec.name, " ".join(cmd))
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=_DOWNLOAD_TIMEOUT, check=False
    )
    if result.returncode != 0:
        raise InstallError(
            f"{spec.name}: {' '.join(cmd)} failed: "
            f"{(result.stderr or result.stdout).strip()[-500:]}"
        )


def uv_run_command(name: str) -> list[str]:
    """Command prefix to run a UV tool: the installed console script if it is on
    PATH, otherwise an ephemeral, version-pinned ``uvx`` invocation."""
    spec = TOOLS[name]
    executable = spec.executable or spec.name
    found = shutil.which(executable)
    if found:
        return [found]
    package = spec.uv_package or spec.name
    return ["uvx", "--from", f"{package}=={spec.version}", executable]
