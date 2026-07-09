"""Cisco AI Defense Skill Scanner: security scan of AI agent skills.

Detects prompt injection, data exfiltration and malicious code patterns in
agent skills (and, with ``--lenient``, Claude Code ``.claude/commands/*.md`` and
flat markdown skill repos). It is a Python tool installed/run via ``uv``
(``deepscan tools install cisco-ai-skill-scanner`` → ``uv tool install``), and
emits SARIF, which flows through the shared parser like every other scanner.
Disable with ``CISCO_AI_SKILL_SCANNER=false``.

In ``--lenient`` mode, when a directory has no ``SKILL.md`` the tool synthesizes
a virtual manifest from the directory's markdown (the first ``*.md``, e.g. a
plain ``README.md``) and reports findings against the *non-existent* path
``SKILL.md`` with no line. We remap such locations back to the real markdown
file the tool actually read, so every finding points at a file that exists.
"""

from __future__ import annotations

from pathlib import Path

from .. import install
from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


def _remap_synthetic_location(target: Path, location: str) -> str:
    """Point a synthetic-manifest location at the real markdown file.

    ``location`` is ``"path"`` or ``"path:line"`` (relative to ``target``). When
    ``path`` does not exist on disk (e.g. the synthesized ``SKILL.md``), remap it
    to the markdown the lenient fallback used - ``sorted(dir.glob("*.md"))[0]``,
    matching the tool's own selection - and default to line 1 (where a manifest's
    frontmatter would live). Real, existing locations are returned unchanged.
    """
    path_part, sep, line_part = location.partition(":")
    if not path_part or (target / path_part).exists():
        return location
    skill_dir = target / Path(path_part).parent
    if not skill_dir.is_dir():
        skill_dir = target
    md_files = sorted(skill_dir.glob("*.md"))
    if not md_files:
        return location
    real = md_files[0].relative_to(target).as_posix()
    return f"{real}:{line_part}" if (sep and line_part) else f"{real}:1"


class CiscoAiSkillScanner(Scanner):
    name = "cisco-ai-skill-scanner"
    family = Family.SAST
    mode = Mode.STATIC
    tool = "cisco-ai-skill-scanner"
    description = "AI agent skill security (prompt injection, exfiltration, malicious code) - Cisco AI Defense"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("cisco-ai-skill-scanner needs a directory target.")
        if not install.is_installed(self.tool):
            raise ScannerSkipped(
                "cisco-ai-skill-scanner is not installed. "
                "Run: deepscan tools install cisco-ai-skill-scanner"
            )
        out = ctx.work_dir / f"{self.name}.sarif"
        cmd = install.uv_run_command(self.tool) + [
            "scan-all",
            str(ctx.target_path),
            "--recursive",
            "--lenient",  # also accept Claude .claude/commands/*.md & flat md repos
            "--format",
            "sarif",
            "--output",
            str(out),
        ]
        code, stdout, stderr = await self._run(cmd)
        if not out.is_file():
            blob = f"{stderr}\n{stdout}".lower()
            if "no skill" in blob or "nothing to scan" in blob:
                raise ScannerSkipped("No AI agent skills found in target.")
            raise RuntimeError(
                f"cisco-ai-skill-scanner exited {code} without a report: "
                f"{stderr.strip()[-300:]}"
            )
        text = out.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.sarif", text)
        findings = parse_sarif(text, tool=self.name, family=self.family)
        # Repoint synthesized-``SKILL.md`` locations at the real markdown file.
        for f in findings:
            f.location = _remap_synthetic_location(ctx.target_path, f.location)
        return findings
