"""Inline ``# nosec`` suppression for taint findings.

A reviewer who has confirmed a flagged sink is safe can annotate the **sink
line** with a comment, and the taint finding for that line is dropped (and
*counted*, never silently discarded - mirrors Bandit's ``# nosec`` metric):

* ``# nosec`` - blanket: suppress every analysis finding on this line.
* ``# nosec sql-injection`` - scoped: suppress only that vuln *kind* on this line.
* ``# nosec CWE-89`` - scoped by CWE id.
* ``# nosec sql-injection, command-injection`` - several kinds/CWEs.

A ``# nosec`` with no recognized kind/CWE token (e.g. ``# nosec reviewed by AppSec``)
is treated as blanket, so a free-text justification never accidentally narrows
the suppression to nothing.

SAFETY: this only ever *reads* the target's source text; nothing is executed.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import sinks

# ``#`` followed by ``nosec`` and whatever trails it on the line.
_NOSEC_RE = re.compile(r"#\s*nosec\b(?P<rest>[^\n]*)", re.IGNORECASE)
# A scoping token is either a ``CWE-<n>`` id or a knowledge-base kind name.
_TOKEN_RE = re.compile(r"cwe-\d+|[a-z][a-z0-9_-]+", re.IGNORECASE)

# Per-file map: line number -> set of scoping tokens (empty set = blanket).
NosecMap = dict[str, dict[int, frozenset[str]]]


def _scoping_tokens(rest: str) -> frozenset[str]:
    """Recognized kind/CWE tokens after ``nosec``; empty ⇒ blanket suppress."""
    known = set(sinks.KINDS)
    out = {
        tok.lower()
        for tok in _TOKEN_RE.findall(rest or "")
        if tok.lower().startswith("cwe-") or tok.lower() in known
    }
    return frozenset(out)


def collect(files: list[Path], root: Path) -> NosecMap:
    """Scan *files* for ``# nosec`` annotations, keyed by root-relative path so
    the keys line up with a finding's ``location`` file part."""
    out: NosecMap = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        lines: dict[int, frozenset[str]] = {}
        for i, line in enumerate(text.splitlines(), start=1):
            m = _NOSEC_RE.search(line)
            if m is not None:
                lines[i] = _scoping_tokens(m.group("rest"))
        if lines:
            out[rel] = lines
    return out


def is_suppressed(nmap: NosecMap, file: str, line: int, kind: str, cwe: str) -> bool:
    """True when a ``# nosec`` on *file:line* covers this finding's kind/CWE."""
    toks = nmap.get(file, {}).get(line)
    if toks is None:
        return False
    if not toks:  # blanket
        return True
    return kind.lower() in toks or (cwe or "").lower() in toks
