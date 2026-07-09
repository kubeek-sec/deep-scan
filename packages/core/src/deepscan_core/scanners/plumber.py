"""``plumber`` scanner - CI/CD pipeline compliance (getplumber/plumber).

Plumber audits pipeline/CI configuration for risky patterns: unpinned container
images and GitHub Actions, action CVEs, branch-protection gaps, unsafe script
execution and secrets leaked in pipeline YAML. We run ``plumber analyze`` over
the target and read its **SARIF** output, parsed into normalized ``Finding``
objects like every other scanner.

**Which provider?** Plumber decides GitHub vs GitLab from the git remote, which
fails when the target has no ``.git`` (a copy-pasted repo) or no configured
remote. We instead detect the provider from on-disk markers - ``.github/
workflows/`` -> GitHub, ``.gitlab-ci.yml`` -> GitLab - and force it with
``--provider``, so a scan runs whenever there is actually CI config to audit.

- **GitHub** is a *local* scan of ``.github/workflows`` (Rego, no token). Plumber
  still needs a git remote to derive ``owner/repo``; when the target has none we
  hand it a throwaway git dir in the scratch area (a placeholder remote, no
  commit) via ``GIT_DIR``/``GIT_WORK_TREE`` so the local scan runs. The scanned
  repo is never modified.
- **GitLab** is *API-only* (it fetches CI config + project settings), so it needs
  a real remote plus ``GITLAB_TOKEN``; with no remote there is nothing to do
  locally and we skip cleanly.

Provider-specific checks (action CVEs, branch protection) use ``GH_TOKEN`` /
``GITHUB_TOKEN`` / ``GITLAB_TOKEN`` from the environment when present and are
skipped otherwise. Plumber requires a ``.plumber.yaml`` policy file; we honour
the target's own if present, otherwise we generate the default one into the
scratch dir (never writing into the scanned repo). Disable with ``PLUMBER=false``.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped

# Placeholder remote used only so plumber's *local* GitHub scan can derive an
# owner/repo when the target has no real remote. It is never contacted (the local
# scan reads .github/workflows off disk); API checks stay off without a token.
_PLACEHOLDER_REMOTE = "https://github.com/local/repository.git"


def _detect_provider(target: Path) -> str | None:
    """The CI provider plumber should audit, from on-disk markers (not the git
    remote): a ``.github/workflows`` dir with at least one YAML -> ``github``, a
    root ``.gitlab-ci.yml``/``.yaml`` -> ``gitlab``. ``None`` when neither is
    present (nothing to audit)."""
    workflows = target / ".github" / "workflows"
    if workflows.is_dir() and any(
        p.suffix in (".yml", ".yaml") and p.is_file() for p in workflows.iterdir()
    ):
        return "github"
    if (target / ".gitlab-ci.yml").is_file() or (target / ".gitlab-ci.yaml").is_file():
        return "gitlab"
    return None


class Plumber(Scanner):
    name = "plumber"
    family = Family.PIPELINE
    mode = Mode.STATIC
    tool = "plumber"
    description = "CI/CD pipeline compliance (action/image pinning, branch protection, pipeline secrets)"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("plumber needs a directory target.")
        binary = self.binary()  # skips cleanly if not installed
        target = ctx.target_path

        provider = _detect_provider(target)
        if provider is None:
            raise ScannerSkipped(
                "no CI/CD config to audit (looked for .github/workflows/*.yml and "
                ".gitlab-ci.yml)."
            )

        # Disable plumber's "newer version available" update check: it makes a
        # network call that, in a restricted-egress container, fails and makes
        # plumber exit non-zero without writing SARIF.
        env = {**os.environ, "PLUMBER_NO_UPDATE_CHECK": "1"}
        has_remote = await self._has_git_remote(target)

        if provider == "gitlab" and not has_remote:
            # GitLab analysis is API-only: it needs the real project path (from
            # the remote) and GITLAB_TOKEN. Nothing can be done locally.
            raise ScannerSkipped(
                ".gitlab-ci.yml found but this target has no git remote; plumber's "
                "GitLab audit needs a remote + GITLAB_TOKEN (scan a cloned repo)."
            )

        config = await self._config(ctx, binary, env)

        analyze_env = env
        if provider == "github" and not has_remote:
            # plumber's local GitHub scan needs a git remote to derive owner/repo;
            # give it a throwaway one in the scratch dir so the scan can proceed.
            analyze_env = await self._synthesize_git_dir(ctx, target, env)

        sarif = ctx.work_dir / "plumber.sarif"
        cmd = [
            str(binary), "analyze", "--provider", provider,
            "--config", str(config), "--sarif", str(sarif),
        ]
        code, stdout, stderr = await self._run(cmd, cwd=target, env=analyze_env)
        if not sarif.is_file():
            raise ScannerSkipped(
                f"plumber produced no SARIF (exit {code}): "
                f"{(stderr or stdout).strip()[-200:] or 'no pipeline config found'}"
            )
        text = sarif.read_text(encoding="utf-8", errors="replace")
        self.save_raw(ctx, "plumber.sarif", text)
        return parse_sarif(text, tool=self.name, family=self.family)

    async def _has_git_remote(self, target: Path) -> bool:
        """True when the target is a git checkout with an ``origin`` remote URL -
        the only case where plumber can auto-derive the provider/project itself."""
        if not (target / ".git").exists():  # dir (clone) or file (worktree/submodule)
            return False
        code, out, _err = await self._run(
            ["git", "remote", "get-url", "origin"], cwd=target
        )
        return code == 0 and bool(out.strip())

    async def _synthesize_git_dir(
        self, ctx: ScanContext, target: Path, env: dict[str, str]
    ) -> dict[str, str]:
        """Build a throwaway git dir under the scratch area with a placeholder
        remote and return an env (``GIT_DIR``/``GIT_WORK_TREE``) that makes the
        target look like a checkout to plumber. No commit is needed and the
        scanned repo is never written to (the ``.git`` lives in ``work_dir``)."""
        git_dir = ctx.work_dir / "plumber-gitdir"
        git_env = {**env, "GIT_DIR": str(git_dir), "GIT_WORK_TREE": str(target)}
        await self._run(["git", "init", "-q"], cwd=target, env=git_env)
        await self._run(
            ["git", "remote", "add", "origin", _PLACEHOLDER_REMOTE],
            cwd=target, env=git_env,
        )
        return git_env

    async def _config(self, ctx: ScanContext, binary: str, env: dict[str, str]) -> Path:
        """The policy file to use: the target's own ``.plumber.yaml`` if present,
        else an operator default in ``config/plumber/`` if provided, else a default
        generated into the scratch dir (the scanned repo is never modified)."""
        own = (ctx.target_path / ".plumber.yaml") if ctx.target_path else None
        if own and own.is_file():
            return own
        operator = self.config_file(".plumber.yaml", "*.yaml", "*.yml")
        if operator is not None:
            return operator
        generated = ctx.work_dir / ".plumber.yaml"
        _code, _out, err = await self._run(
            [str(binary), "config", "generate", "--output", str(generated), "--force"],
            cwd=ctx.work_dir,
            env=env,
        )
        if not generated.is_file():
            raise ScannerSkipped(
                f"plumber needs a .plumber.yaml and the default could not be generated: "
                f"{err.strip()[-200:]}"
            )
        return generated
