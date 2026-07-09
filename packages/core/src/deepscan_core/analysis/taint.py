"""Precise Python AST taint analysis (sanitizer-aware, cross-function).

Builds a per-function data-flow view from Python source using the standard
``ast`` module and hands it to the shared, language-agnostic propagation core in
:mod:`taint_core`, which traces source → sink paths that cross function
boundaries without passing a sanitizer. This is the high-confidence engine for
Python; it is the cross-function reach that single-line SAST misses.

This module owns only the Python-`ast`-specific *collector*. The traversal
itself (:func:`find_taint_paths`, :class:`FuncNode`, :class:`TaintPath`) lives in
:mod:`taint_core` and is shared with the tree-sitter engine (:mod:`ts_taint`),
so every language uses one propagation algorithm.

SAFETY: source is parsed with ``ast`` only - never imported, deserialized or
executed. Sink names (``pickle.loads``, ``yaml.load``, …) are matched as
strings, never invoked.
"""

from __future__ import annotations

import ast
import warnings
from pathlib import Path

from . import sinks
from .taint_core import FuncNode, TaintPath, _resolve, _short, find_taint_paths

# Re-exported so existing callers/tests can keep importing these from ``taint``.
__all__ = [
    "FuncNode", "TaintPath", "find_taint_paths", "_resolve", "_short",
    "build_graph", "analyze_python",
]

_PY = "python"
_SOURCE_CALLS = sinks.SOURCES[_PY]
_SOURCE_ATTRS = sinks.SOURCE_ATTRS[_PY]
_SINKS = sinks.SINKS[_PY]
_SANITIZERS = sinks.SANITIZERS[_PY]


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map each imported local name to its canonical dotted form, so a callee
    can be matched against the knowledge base by its real qualified name.

    ``from os import system`` → ``system`` → ``os.system``;
    ``from os import system as run`` → ``run`` → ``os.system``;
    ``import subprocess as sp`` → ``sp`` → ``subprocess``.

    This is the single biggest precision fix for the Python collector: without
    it ``from os import system as run; run(x)`` matches neither ``os.system`` nor
    ``system`` and the command-injection sink is silently missed (mirrors
    Bandit's ``import_aliases`` in ``node_visitor.py``).
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:  # bind the top-level package to itself (no-op resolve)
                    head = a.name.split(".", 1)[0]
                    aliases.setdefault(head, head)
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:  # relative "from . import x" - no canonical base
                continue
            for a in node.names:
                if a.name == "*":
                    continue
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _resolve_alias(name: str, aliases: dict[str, str]) -> str:
    """Rewrite a callee's leading segment through the import alias map.

    Only the head segment is rewritten (``sp.Popen`` → ``subprocess.Popen``),
    and only for genuinely-imported names, so a local ``def system()`` is never
    rewritten into the ``os.system`` sink.
    """
    if not name:
        return name
    head, sep, rest = name.partition(".")
    base = aliases.get(head)
    if base is None:
        return name
    return f"{base}{sep}{rest}" if rest else base


def _names_in(node: ast.AST) -> list[str]:
    found: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.append(child.id)
        elif isinstance(child, ast.Attribute):
            dotted = _dotted(child)
            if dotted:
                found.append(dotted)
    return found


def _arg_names(call: ast.Call) -> list[str]:
    names: list[str] = []
    for arg in list(call.args) + [kw.value for kw in call.keywords]:
        names.extend(_names_in(arg))
    return names


def _arg_slots(call: ast.Call) -> list[tuple[object, list[str]]]:
    """Per-argument source-names tagged by their slot: a 0-based position for a
    positional arg (``"*"`` for ``*args``), or the keyword name for a kwarg
    (``"**"`` for ``**kwargs``). Lets a sink flag only its dangerous parameter."""
    slots: list[tuple[object, list[str]]] = []
    for i, arg in enumerate(call.args):
        key: object = "*" if isinstance(arg, ast.Starred) else i
        slots.append((key, _names_in(arg)))
    for kw in call.keywords:
        slots.append((kw.arg if kw.arg is not None else "**", _names_in(kw.value)))
    return slots


def _is_safe_sink_call(call: ast.Call, callee: str) -> bool:
    """Recognise the safe form of a dangerous API so patched code is not
    flagged. Conservative: only well-known safe shapes return True."""
    short = callee.rsplit(".", 1)[-1]
    keywords = {kw.arg: kw.value for kw in call.keywords}
    shell_true = (
        isinstance(keywords.get("shell"), ast.Constant)
        and keywords["shell"].value is True
    )
    if short in {"execute", "executemany"} and len(call.args) >= 2:
        return True  # parameterized query: value passed out-of-band
    if short in {"run", "call", "Popen", "check_output", "check_call"}:
        if call.args and isinstance(call.args[0], (ast.List, ast.Tuple)) and not shell_true:
            return True
    if short == "load" and "yaml" in callee:
        # SafeLoader passed by keyword (``Loader=yaml.SafeLoader``) or
        # positionally (``yaml.load(text, SafeLoader)``) makes the load safe.
        loader = keywords.get("Loader") or (call.args[1] if len(call.args) >= 2 else None)
        if loader is not None and "Safe" in _dotted(loader):
            return True
    if short == "load" and "torch" in callee:
        # torch.load(..., weights_only=True) cannot reconstruct arbitrary objects.
        wo = keywords.get("weights_only")
        if isinstance(wo, ast.Constant) and wo.value is True:
            return True
    return False


def _rhs_sanitizer_kinds(value: ast.AST | None, aliases: dict[str, str]) -> frozenset[str]:
    """Vuln *kinds* neutralised by the sanitizer call(s) on this RHS (empty when
    none). A value built with ``html.escape`` is cleared for ``xss`` only, so it
    still trips a SQL sink."""
    if value is None:
        return frozenset()
    kinds: set[str] = set()
    for child in ast.walk(value):
        if isinstance(child, ast.Call):
            callee = _resolve_alias(_dotted(child.func), aliases)
            k = _SANITIZERS.get(callee) or _SANITIZERS.get(callee.rsplit(".", 1)[-1])
            if k:
                kinds |= k
    return frozenset(kinds)


class _Collector(ast.NodeVisitor):
    def __init__(self, file: str, aliases: dict[str, str] | None = None):
        self.file = file
        self.aliases = aliases or {}
        self.funcs: dict[str, FuncNode] = {}
        self._stack: list[str] = []

    def _visit_func(self, node):
        qual = ".".join(self._stack + [node.name])
        fn = FuncNode(
            qualname=qual, file=self.file, lineno=node.lineno, family=_PY,
            params=[a.arg for a in node.args.args if a.arg != "self"],
        )
        self.funcs[qual] = fn
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                callee = _resolve_alias(_dotted(child.func), self.aliases)
                if callee:
                    fn.calls.append((
                        callee, getattr(child, "lineno", node.lineno),
                        _arg_names(child), _is_safe_sink_call(child, callee),
                        _arg_slots(child),
                    ))
            elif isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                names: list[str] = []
                for t in targets:
                    names.extend(_names_in(t))
                rhs = _names_in(child.value) if child.value is not None else []
                if isinstance(child, ast.AugAssign):
                    rhs = rhs + names  # x += y keeps x's prior taint
                if names:
                    fn.assigns.append(
                        (names, rhs, _rhs_sanitizer_kinds(child.value, self.aliases))
                    )
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func


def build_graph(files: list[Path], root: Path) -> dict[str, FuncNode]:
    funcs: dict[str, FuncNode] = {}
    for path in files:
        try:
            with warnings.catch_warnings():
                # Parsing untrusted target code: a SyntaxWarning (e.g. an invalid
                # escape sequence like "\d") is about the *scanned* project's code,
                # not ours - suppress it so it doesn't flood the worker log.
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(
                    path.read_text(encoding="utf-8", errors="replace"), filename=str(path)
                )
        except (SyntaxError, OSError, ValueError):
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        collector = _Collector(rel, _collect_import_aliases(tree))
        collector.visit(tree)
        # Key by file + qualname so same-named functions in different files
        # (e.g. a vulnerable file and its *_patched sibling) do not collide.
        for qual, fn in collector.funcs.items():
            funcs[f"{rel}::{qual}"] = fn
    return funcs


def analyze_python(
    files: list[Path],
    root: Path,
    *,
    deadline: float | None = None,
    should_stop=None,
) -> list[TaintPath]:
    """Convenience: build the graph for the Python files and return taint paths."""
    py = [f for f in files if f.suffix.lower() in (".py", ".pyw")]
    if not py:
        return []
    return find_taint_paths(build_graph(py, root), deadline=deadline, should_stop=should_stop)
