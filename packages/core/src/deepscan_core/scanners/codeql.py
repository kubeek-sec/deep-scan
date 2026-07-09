"""``codeql`` scanner - wrap the CodeQL CLI (deep interprocedural SAST).

CodeQL gives type-aware, interprocedural data-flow/taint analysis far beyond our
built-in ``analysis`` scanner. We do not build CodeQL or touch its database
format: we shell out to the **CodeQL CLI bundle** (free download; set it on PATH
or via ``DEEPSCAN_CODEQL_BIN``) to (1) create a database per detected language
and (2) analyze it with that language's security queries, emitting **SARIF** -
which we parse into the same normalized ``Finding`` objects as every other
scanner.

Off by default - opt in with ``CODEQL=true``. When enabled it does no work until
the CodeQL CLI is installed (it then skips with an install hint), so it never
silently disappears. It is slow/RAM-heavy and on private code needs a GitHub
licence. Buildless for Python/JS/Ruby; **TypeScript** additionally needs
``node`` on PATH (its extractor shells out to Node.js - without it the
``javascript`` database create fails). Java/C# try ``--build-mode=none``;
Go/C++/Swift need a build command (``DEEPSCAN_CODEQL_BUILD_<LANG>``) or are
skipped with a clear reason. When ``database create``/``analyze`` fails the skip
reason carries the actual cause (parsed from CodeQL's log) and the full command
log is saved under ``raw/`` for debugging.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .. import config
from ..log import get_logger
from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped

_log = get_logger("scanner")
_DEFAULT_TIMEOUT = 3600  # CodeQL is slow; allow an hour by default

# file extension → CodeQL language id
_EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".java": "java",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".c": "cpp", ".h": "cpp", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".swift": "swift",
}
_BUILDLESS = {"python", "javascript", "ruby"}          # no build needed at all
_BUILD_MODE_NONE = {"java", "csharp"}                  # CLI can extract without a build
_NEEDS_BUILD = {"go", "cpp", "swift"}                  # need a real build command

# Log lines that merely restate "it failed" without saying *why* - we skip these
# when pulling the cause out of CodeQL's (very noisy) build log.
_LOG_WRAPPERS = (
    "a fatal error occurred", "spawned process exited", "exit status",
    "exiting with code", "command failed", "tried to run",
)


def _brief_error(out: str, err: str) -> str:
    """Pull the human-readable cause out of CodeQL's noisy build log.

    CodeQL prints hundreds of ``[ts] [build-stdout] …`` lines plus a Java stack
    trace; the real reason (e.g. "Could not start Node.js. It is required for
    TypeScript extraction.") is a couple of plain lines near the end. Return
    those, stripped of the log prefixes, so the report's skip reason is
    actionable instead of a bare "db create failed".
    """
    substantive: list[str] = []
    for raw in ((err or "") + "\n" + (out or "")).splitlines():
        line = raw.strip()
        while line.startswith("[") and "]" in line:   # drop "[ts] [stream] " prefixes
            line = line[line.index("]") + 1:].strip()
        if not line or line.startswith(("at ", "...", "Caused by:")):
            continue                                    # blank line / Java stack frame
        if any(w in line.lower() for w in _LOG_WRAPPERS):
            continue                                    # wrapper, not a cause
        substantive.append(line)
    return " ".join(substantive[-2:])[:240]


def detect_languages(target: Path) -> set[str]:
    """CodeQL languages present under *target* (by file extension)."""
    skip = {".git", ".venv", "node_modules", "__pycache__", "vendor", "dist", "build"}
    langs: set[str] = set()
    for p in target.rglob("*"):
        if p.is_file() and not (skip & set(p.parts)):
            lang = _EXT_LANG.get(p.suffix.lower())
            if lang:
                langs.add(lang)
    return langs


class CodeQL(Scanner):
    name = "codeql"
    family = Family.SAST
    mode = Mode.STATIC
    tool = "codeql"  # managed via `deepscan tools install codeql` (a directory tree)
    # Off by default (slow, RAM-heavy, needs the ~1 GB CLI bundle). Opt in with
    # CODEQL=true; once enabled it still skips cleanly (with an install hint)
    # until the CLI bundle is installed.
    enabled_by_default = False
    description = "CodeQL interprocedural taint/dataflow SAST (CodeQL CLI bundle)"

    @property
    def timeout(self) -> int:
        return config.timeout_for(self.name, default=_DEFAULT_TIMEOUT)

    def _resolve_codeql(self) -> str | None:
        """Resolve the CodeQL launcher: explicit env → managed install → PATH."""
        raw = config.get("DEEPSCAN_CODEQL_BIN")
        if raw:
            return shutil.which(raw) or (raw if Path(raw).is_file() else None)
        from ..install import tool_path

        managed = tool_path("codeql")
        if managed:
            return str(managed)
        return shutil.which("codeql")

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("codeql needs a directory target.")
        codeql = self._resolve_codeql()
        if codeql is None:
            raise ScannerSkipped(
                "CodeQL CLI not found. Run `deepscan tools install codeql`, or put "
                "`codeql` on PATH / set DEEPSCAN_CODEQL_BIN."
            )

        target = ctx.target_path.resolve()  # absolute → --source-root is unambiguous
        languages = detect_languages(target)
        if not languages:
            raise ScannerSkipped("no CodeQL-supported source files found.")

        findings: list[Finding] = []
        ran_any = False
        skipped: list[str] = []
        for lang in sorted(languages):
            db = ctx.work_dir / f"codeqldb-{lang}"
            create = self._create_cmd(codeql, lang, target, db)
            if create is None:
                skipped.append(f"{lang} (needs DEEPSCAN_CODEQL_BUILD_{lang.upper()})")
                continue
            code, out, err = await self._run(create, cwd=target)
            if code != 0:
                reason = _brief_error(out, err)
                self.save_raw(ctx, f"codeql-{lang}-create.log", f"$ {' '.join(create)}\n\n{out}\n{err}")
                _log.warning("codeql: db create failed for %s: %s", lang, reason or err.strip()[-300:])
                skipped.append(
                    f"{lang} (db create failed: {reason})" if reason else f"{lang} (db create failed)"
                )
                continue

            sarif_path = ctx.work_dir / f"codeql-{lang}.sarif"
            analyze = [
                codeql, "database", "analyze", str(db), config.codeql_query_pack(lang),
                "--format", "sarif-latest", "--output", str(sarif_path),
                "--threads", config.codeql_threads(),
                # Fetch the standard query pack if it isn't already cached
                # (the CLI bundle ships no packs); install pre-downloads them too.
                "--download", *config.codeql_extra_args(),
            ]
            code, out, err = await self._run(analyze, cwd=target)
            if code != 0 or not sarif_path.is_file():
                reason = _brief_error(out, err)
                self.save_raw(ctx, f"codeql-{lang}-analyze.log", f"$ {' '.join(analyze)}\n\n{out}\n{err}")
                _log.warning("codeql: analyze failed for %s: %s", lang, reason or err.strip()[-300:])
                skipped.append(
                    f"{lang} (analyze failed: {reason})" if reason else f"{lang} (analyze failed)"
                )
                continue
            text = sarif_path.read_text(encoding="utf-8", errors="replace")
            self.save_raw(ctx, f"codeql-{lang}.sarif", text)
            findings.extend(parse_sarif(text, tool=self.name, family=self.family))
            ran_any = True

        if not ran_any:
            raise ScannerSkipped(
                "codeql produced no results - " + ("; ".join(skipped) or "no language analyzed")
            )
        if skipped:
            _log.info("codeql: skipped %s", "; ".join(skipped))
        return findings

    def _create_cmd(self, codeql: str, lang: str, target: Path, db: Path) -> list[str] | None:
        cmd = [
            codeql, "database", "create", str(db), "--language", lang,
            "--source-root", str(target), "--overwrite", "--threads", config.codeql_threads(),
        ]
        build = config.codeql_build_command(lang)
        if lang in _BUILDLESS:
            return cmd
        if build:
            return cmd + ["--command", build]
        if lang in _BUILD_MODE_NONE:
            return cmd + ["--build-mode=none"]
        # go / cpp / swift without a build command: cannot extract reliably.
        return None
