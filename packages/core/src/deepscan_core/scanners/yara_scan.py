"""``yara`` scanner - signature detection of malicious intent.

Runs a vendored set of YARA rules (from Cisco's Apache-2.0 mcp-scanner, see
``data/yara_rules/NOTICE.md``) over a project's source code and text/description
files to flag bad-intent patterns: prompt injection, tool poisoning,
command/SQL/script/code injection, credential harvesting, data exfiltration and
system manipulation. Pure-Python (``yara-python``), no managed binary; disable
with ``YARA=false``.

SAFETY: rules are compiled and matched against file *content* only - nothing is
imported or executed.
"""

from __future__ import annotations

from pathlib import Path

from .. import config
from ..models import Family, Finding, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped, packaged_rules_dir

# threat_type (from a rule's meta) → (baseline severity, CWE). Mirrors the
# upstream threat taxonomy; unknown types fall back to MEDIUM / no CWE.
_THREAT_MAP: dict[str, tuple[Severity, str]] = {
    "PROMPT INJECTION": (Severity.HIGH, "CWE-1427"),  # input used for LLM prompting
    "TOOL POISONING": (Severity.HIGH, "CWE-506"),     # embedded malicious code
    "CODE EXECUTION": (Severity.LOW, "CWE-94"),
    "INJECTION ATTACK": (Severity.HIGH, "CWE-74"),
    "CREDENTIAL HARVESTING": (Severity.HIGH, "CWE-522"),
    "DATA EXFILTRATION": (Severity.HIGH, "CWE-200"),
    "SYSTEM MANIPULATION": (Severity.HIGH, "CWE-77"),
}

# Files worth matching: source code + the text/markdown/config files where tool
# and skill descriptions (and hidden instructions) live.
_SCAN_EXTS = {
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs", ".c", ".h", ".cpp", ".cc",
    ".sh", ".bash", ".ps1",
    ".md", ".markdown", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".html", ".htm", ".xml",
}
_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".tox", ".nox", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".idea", "target",
}
_MAX_FILE_BYTES = 4 * 1024 * 1024

_rules_cache = None


def _yara_sources() -> dict[str, str]:
    """The ``{rule_name: source}`` map to compile.

    Packaged defaults (``data/scanner_rules/yara/*.yara``) plus any operator
    rules in ``config/yara/*.yara`` - the runtime dir is read last, so a custom
    file with the same stem overrides the packaged default while new files just
    add to the set.
    """
    sources: dict[str, str] = {}
    dirs = [packaged_rules_dir("yara")]
    runtime = config.scanner_config_dir("yara")
    if runtime is not None:
        dirs.append(runtime)
    for d in dirs:
        for p in sorted(Path(str(d)).glob("*.yara")):
            sources[p.stem] = p.read_text(encoding="utf-8")
    return sources


def _compiled_rules():
    """Compile the YARA rules (packaged defaults + ``config/yara`` overrides) once."""
    global _rules_cache
    if _rules_cache is None:
        import yara

        sources = _yara_sources()
        if not sources:
            raise ScannerSkipped(
                "no YARA rules found (data/scanner_rules/yara or config/yara)."
            )
        _rules_cache = yara.compile(sources=sources)
    return _rules_cache


def _match_offset_and_ids(match) -> tuple[int, list[str]]:
    """First matched byte offset and the matched string identifiers, across
    yara-python API versions (4.3+ uses ``StringMatch.instances``)."""
    offsets: list[int] = []
    ids: list[str] = []
    for s in match.strings:
        instances = getattr(s, "instances", None)
        if instances is not None:  # yara-python >= 4.3
            ids.append(getattr(s, "identifier", "?"))
            offsets.extend(i.offset for i in instances)
        elif isinstance(s, tuple):  # older API: (offset, identifier, data)
            offsets.append(s[0])
            ids.append(s[1])
    return (min(offsets) if offsets else 0), ids


class Yara(Scanner):
    name = "yara"
    family = Family.MALWARE
    mode = Mode.STATIC
    tool = None  # pure-Python (yara-python); no managed binary
    description = "Malicious-intent signatures (YARA): prompt injection, tool poisoning, injection, exfiltration"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("yara scanner needs a directory target.")
        try:
            rules = _compiled_rules()
        except ImportError as exc:  # yara-python missing
            raise ScannerSkipped(f"yara-python not available: {exc}") from exc

        findings: list[Finding] = []
        scanned = 0
        for path in self._iter_files(ctx.target_path):
            try:
                content = path.read_bytes()
            except OSError:
                continue
            if not content or len(content) > _MAX_FILE_BYTES:
                continue
            try:
                matches = rules.match(data=content)
            except Exception:  # noqa: BLE001 - never let one file fail the scan
                continue
            scanned += 1
            if not matches:
                continue
            text = content.decode("utf-8", "replace")
            rel = self._rel(path, ctx.target_path)
            for match in matches:
                findings.append(self._to_finding(match, text, rel))

        if ctx.raw_dir is not None:
            import json

            self.save_raw(ctx, "yara.json", json.dumps(
                {"files_scanned": scanned, "matches": len(findings),
                 "findings": [f.to_dict() for f in findings]}, indent=2))
        return findings

    def _to_finding(self, match, text: str, rel: str) -> Finding:
        meta = match.meta or {}
        threat = str(meta.get("threat_type") or match.rule).upper()
        severity, cwe = _THREAT_MAP.get(threat, (Severity.MEDIUM, ""))
        offset, ids = _match_offset_and_ids(match)
        line = text.count("\n", 0, offset) + 1 if offset else 1
        desc = meta.get("description") or match.rule
        return Finding(
            tool=self.name,
            family=self.family,
            rule=match.rule,
            severity=severity,
            message=f"{threat.title()}: {desc}",
            location=f"{rel}:{line}",
            cwes=[cwe] if cwe else [],
            extra={
                "engine": "yara",
                "threat_type": threat,
                "classification": meta.get("classification"),
                "matched_strings": sorted(set(ids))[:12],
            },
        )

    def _iter_files(self, root: Path):
        if root.is_file():
            yield root
            return
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            if _SKIP_DIRS & set(path.parts):
                continue
            if path.suffix.lower() in _SCAN_EXTS:
                yield path

    @staticmethod
    def _rel(path: Path, root: Path) -> str:
        try:
            return str(path.relative_to(root))
        except ValueError:
            return path.name
