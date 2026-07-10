"""Per-ecosystem resolvers.

P1 ships the ecosystems whose lock step provably runs NO project/dependency code
(metadata-only / no build): npm, go, cargo, bundler. Each points its package
manager at the Nexus mirror (``<nexus>/repository/<repo>/``) so no direct
internet is needed.

Deferred to P2 (they can execute code during resolution -> need the gVisor
sandbox first): maven & gradle (plugins), nuget/.NET (MSBuild targets), and
Python via uv (may build dependency sdists to read metadata). Python projects
that ship a pinned ``requirements.txt`` need no resolver anyway - Trivy reads it
directly, offline.
"""

from __future__ import annotations

from pathlib import Path

from .base import Resolver


class NpmResolver(Resolver):
    ecosystem = "npm"
    tool = "npm"
    manifests = ("package.json",)
    # Any of these means the tree is already resolved (yarn/pnpm included so we
    # don't clobber a project that locks with a different manager).
    lockfiles = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")

    def command(self, root: Path) -> list[str]:
        # --package-lock-only: compute the lockfile from registry metadata WITHOUT
        # installing node_modules; --ignore-scripts: never run lifecycle scripts.
        # Together => metadata-only, zero project code executed.
        return ["npm", "install", "--package-lock-only", "--ignore-scripts",
                "--no-audit", "--no-fund", "--loglevel=error"]

    def environment(self, base: dict[str, str], nexus_url: str | None,
                    work: Path) -> dict[str, str]:
        base["npm_config_cache"] = str(work / "npm-cache")
        base["npm_config_audit"] = "false"
        base["npm_config_fund"] = "false"
        base["npm_config_update_notifier"] = "false"
        if nexus_url:
            base["npm_config_registry"] = f"{nexus_url}/repository/npm-proxy/"
        return base


class GoResolver(Resolver):
    ecosystem = "go"
    tool = "go"
    manifests = ("go.mod",)
    lockfiles = ("go.sum",)

    def command(self, root: Path) -> list[str]:
        # Downloads the module graph and records checksums into go.sum. Go never
        # runs package code on download.
        return ["go", "mod", "download", "all"]

    def environment(self, base: dict[str, str], nexus_url: str | None,
                    work: Path) -> dict[str, str]:
        base["GOFLAGS"] = "-mod=mod"      # allow writing go.sum
        base["GOSUMDB"] = "off"           # don't reach out to sum.golang.org
        base["GOPATH"] = str(work / "gopath")
        base["GOMODCACHE"] = str(work / "gomodcache")
        if nexus_url:
            base["GOPROXY"] = f"{nexus_url}/repository/go-proxy/"
        return base


class CargoResolver(Resolver):
    ecosystem = "cargo"
    tool = "cargo"
    manifests = ("Cargo.toml",)
    lockfiles = ("Cargo.lock",)

    def command(self, root: Path) -> list[str]:
        # Resolves versions and writes Cargo.lock; does NOT compile (no build.rs
        # runs), so no project/dependency code executes.
        return ["cargo", "generate-lockfile"]

    def environment(self, base: dict[str, str], nexus_url: str | None,
                    work: Path) -> dict[str, str]:
        cargo_home = work / "cargo-home"
        cargo_home.mkdir(parents=True, exist_ok=True)
        base["CARGO_HOME"] = str(cargo_home)
        if nexus_url:
            # Source replacement: crates.io index -> Nexus sparse index. Kept in
            # CARGO_HOME (scratch), never written into the scanned tree.
            (cargo_home / "config.toml").write_text(
                "[source.crates-io]\n"
                'replace-with = "nexus"\n\n'
                "[source.nexus]\n"
                f'registry = "sparse+{nexus_url}/repository/cargo-proxy/"\n',
                encoding="utf-8",
            )
        return base


class BundlerResolver(Resolver):
    ecosystem = "bundler"
    tool = "bundle"
    manifests = ("Gemfile",)
    lockfiles = ("Gemfile.lock",)

    def command(self, root: Path) -> list[str]:
        # Resolves and writes Gemfile.lock without installing gems (no native
        # extension builds, no gem code executed).
        return ["bundle", "lock"]

    def environment(self, base: dict[str, str], nexus_url: str | None,
                    work: Path) -> dict[str, str]:
        base["BUNDLE_USER_HOME"] = str(work / "bundle-home")
        if nexus_url:
            # bundler mirror env form: dots in the host -> "__".
            base["BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG"] = (
                f"{nexus_url}/repository/rubygems-proxy"
            )
        return base


# Order is irrelevant - each resolver is independent and keyed on its own
# manifest. A project can trigger several (a polyglot monorepo).
RESOLVERS: list[Resolver] = [
    NpmResolver(),
    GoResolver(),
    CargoResolver(),
    BundlerResolver(),
]
