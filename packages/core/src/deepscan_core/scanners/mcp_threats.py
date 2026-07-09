"""``mcp-threats`` scanner - malicious-intent patterns in natural-language text.

Complements the ``yara`` and ``analysis`` scanners by flagging LLM/agent threat
phrases that hide in docstrings, tool/skill descriptions, prompts and markdown -
instruction override, hidden behavior, tool poisoning, data exfiltration and
credential coercion - plus **invisible/bidi Unicode** used to smuggle hidden
instructions (which YARA cannot meaningfully match).

The pattern sets are distilled from Cisco's Apache-2.0 mcp-scanner (its
prompt_injection / tool_poisoning YARA rules and prompt-defense phrase lists).
Static text matching only; nothing is executed. Disable with ``MCP_THREATS=false``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .. import config
from ..models import Family, Finding, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped, packaged_rules_dir

# Minimal hard-coded fallback used only if the packaged patterns.json is missing
# (so the scanner still does something rather than crash). category -> (sev, cwe,
# [regex]). The full set lives in data/scanner_rules/mcp-threats/patterns.json.
_FALLBACK_PATTERNS: dict[str, tuple[Severity, str, list[str]]] = {
    "instruction-override": (Severity.HIGH, "CWE-1427", [
        r"\bdisregard\s+(?:all\s+)?safety\s+(?:guidelines|rules|instructions)\b",
    ]),
}


def _load_raw_patterns() -> dict[str, tuple[Severity, str, list[str]]]:
    """Load ``{category: (severity, cwe, [regex])}`` from the packaged
    patterns.json, overlaid by a runtime ``config/mcp-threats/patterns.json``
    (a runtime category replaces the packaged one of the same name and new
    categories are added). Falls back to a tiny built-in set if nothing loads.
    """
    merged: dict[str, dict] = {}
    sources = [packaged_rules_dir("mcp-threats") / "patterns.json"]
    runtime = config.scanner_config_dir("mcp-threats")
    if runtime is not None:
        sources.append(runtime / "patterns.json")
    for path in sources:
        try:
            data = json.loads(Path(str(path)).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            merged.update(data)
    if not merged:
        return dict(_FALLBACK_PATTERNS)
    return {
        cat: (Severity(spec["severity"]), spec.get("cwe", ""), list(spec.get("patterns", [])))
        for cat, spec in merged.items()
    }


_PATTERNS: dict[str, tuple[Severity, str, list[re.Pattern]]] = {
    cat: (sev, cwe, [re.compile(p, re.IGNORECASE) for p in pats])
    for cat, (sev, cwe, pats) in _load_raw_patterns().items()
}

# Invisible / bidirectional / tag Unicode used to smuggle hidden instructions:
# soft hyphen, zero-width + LRM/RLM, bidi embeddings/overrides, word-joiner /
# invisible operators, bidi isolates + deprecated format chars, BOM, and the
# Unicode Tags block. (Escapes only - never literal invisibles in the source.)
_BOM = "\ufeff"
_INVISIBLE = re.compile(
    "[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]"
    "|[\U000e0000-\U000e007f]"
)

_SCAN_EXTS = {
    ".md", ".markdown", ".txt", ".rst", ".json", ".yaml", ".yml", ".toml",
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs",
}
_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".tox", ".nox", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".idea", "target",
}
_MAX_FILE_BYTES = 4 * 1024 * 1024


class McpThreats(Scanner):
    name = "mcp-threats"
    family = Family.MALWARE
    mode = Mode.STATIC
    tool = None  # pure-Python pattern engine; no managed binary
    description = "Malicious-intent text patterns: prompt injection, tool poisoning, exfiltration, invisible Unicode"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("mcp-threats scanner needs a directory target.")
        findings: list[Finding] = []
        for path in self._iter_files(ctx.target_path):
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if not raw or len(raw) > _MAX_FILE_BYTES:
                continue
            text = raw.decode("utf-8", "replace")
            rel = self._rel(path, ctx.target_path)
            findings.extend(self._scan_text(text, rel))
        if ctx.raw_dir is not None:
            import json

            self.save_raw(ctx, "mcp-threats.json", json.dumps(
                {"matches": len(findings), "findings": [f.to_dict() for f in findings]},
                indent=2))
        return findings

    def _scan_text(self, text: str, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        for category, (severity, cwe, patterns) in _PATTERNS.items():
            for pat in patterns:
                m = pat.search(text)
                if not m:
                    continue
                line = text.count("\n", 0, m.start()) + 1
                snippet = " ".join(m.group(0).split())[:120]
                findings.append(Finding(
                    tool=self.name,
                    family=self.family,
                    rule=category,
                    severity=severity,
                    message=f"{category.replace('-', ' ').title()}: {snippet!r}",
                    location=f"{rel}:{line}",
                    cwes=[cwe],
                    extra={"engine": "mcp-threats", "category": category},
                ))
                break  # one finding per category per file
        findings.extend(self._scan_unicode(text, rel))
        return findings

    def _scan_unicode(self, text: str, rel: str) -> list[Finding]:
        # Ignore a single leading BOM (legitimate); flag anything else.
        offset = 1 if text[:1] == _BOM else 0
        m = _INVISIBLE.search(text, offset)
        if not m:
            return []
        line = text.count("\n", 0, m.start()) + 1
        codepoints = sorted({f"U+{ord(c):04X}" for c in _INVISIBLE.findall(text[offset:])})
        return [Finding(
            tool=self.name,
            family=self.family,
            rule="invisible-unicode",
            severity=Severity.MEDIUM,
            message=f"Invisible/bidirectional Unicode ({', '.join(codepoints[:8])}) "
                    "may smuggle hidden instructions",
            location=f"{rel}:{line}",
            cwes=["CWE-1007"],
            extra={"engine": "mcp-threats", "category": "invisible-unicode",
                   "codepoints": codepoints[:16]},
        )]

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
