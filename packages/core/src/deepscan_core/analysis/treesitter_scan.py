"""Multi-language dangerous call-site detection via tree-sitter.

For the non-Python languages graphoofy ships grammars for, this finds call
expressions whose callee matches a sink in the knowledge base and reports them
as **risk zones**. It is structural, not a full data-flow engine: it does not
prove a tainted value reaches the sink. Instead it records two coarse signals
the engine uses to set severity and confidence:

* ``unsanitized`` - no sanitizer call appears in the enclosing function.
* ``input_nearby`` - an untrusted-source token appears in the enclosing
  function (so the sink plausibly handles external input).

SAFETY: files are parsed with tree-sitter only; nothing is executed. Sink names
are matched as strings.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path

from . import sinks

# extension → (tree-sitter module, language-function name, kb family)
_TS: dict[str, tuple[str, str, str]] = {
    # Python is also covered by the precise AST taint engine; the tree-sitter pass
    # adds coarse risk-zone detection (call-sites) so simple sinks are still caught
    # when taint can't prove a cross-function flow. Overlaps are deduped in engine.
    ".py": ("tree_sitter_python", "language", "python"),
    ".pyw": ("tree_sitter_python", "language", "python"),
    ".js": ("tree_sitter_javascript", "language", "js"),
    ".jsx": ("tree_sitter_javascript", "language", "js"),
    ".mjs": ("tree_sitter_javascript", "language", "js"),
    ".cjs": ("tree_sitter_javascript", "language", "js"),
    ".ts": ("tree_sitter_typescript", "language_typescript", "js"),
    ".tsx": ("tree_sitter_typescript", "language_tsx", "js"),
    ".java": ("tree_sitter_java", "language", "java"),
    ".go": ("tree_sitter_go", "language", "go"),
    ".rb": ("tree_sitter_ruby", "language", "ruby"),
    ".php": ("tree_sitter_php", "language_php", "php"),
    ".cs": ("tree_sitter_c_sharp", "language", "csharp"),
    ".rs": ("tree_sitter_rust", "language", "rust"),
    ".c": ("tree_sitter_c", "language", "c"),
    ".h": ("tree_sitter_c", "language", "c"),
    ".cpp": ("tree_sitter_cpp", "language", "c"),
    ".cc": ("tree_sitter_cpp", "language", "c"),
    ".cxx": ("tree_sitter_cpp", "language", "c"),
    ".hpp": ("tree_sitter_cpp", "language", "c"),
}

# node types (across grammars) that denote a call / construction.
_CALL_TYPES = frozenset({
    "call", "call_expression", "method_invocation", "function_call_expression",
    "member_call_expression", "scoped_call_expression", "invocation_expression",
    "object_creation_expression", "new_expression", "macro_invocation",
    "method_call", "command", "command_call",
})

# node types that delimit an enclosing "function" for locality checks.
_FUNC_TYPES = frozenset({
    "function_declaration", "function_definition", "function_item",
    "method_declaration", "method_definition", "method", "func_literal",
    "constructor_declaration", "function_expression", "arrow_function",
    "local_function_statement", "lambda",
})

_parser_cache: dict[str, object] = {}


@dataclass
class SinkHit:
    callee: str
    kind: str
    cwe: str
    file: str
    line: int
    unsanitized: bool
    input_nearby: bool


def _load_parser(ext: str):
    """Return a tree-sitter Parser for *ext*, or None if the grammar is absent."""
    if ext in _parser_cache:
        return _parser_cache[ext]
    spec = _TS.get(ext)
    parser = None
    if spec is not None:
        module, fn_name, _family = spec
        try:
            from tree_sitter import Language, Parser

            mod = importlib.import_module(module)
            lang_fn = getattr(mod, fn_name, None) or getattr(mod, "language", None)
            if lang_fn is not None:
                parser = Parser(Language(lang_fn()))
        except Exception:
            parser = None
    _parser_cache[ext] = parser
    return parser


def _callee_text(node, source: bytes) -> str:
    """Callee string of a call node: the text up to its **argument list**.

    Uses the call node's argument-list child (``argument_list`` / ``arguments``,
    across grammars) so chained calls keep their tail - ``Runtime.getRuntime().exec(x)``
    → ``Runtime.getRuntime.exec`` (whose ``exec`` suffix matches), where a naive
    split on the first ``(`` would wrongly stop at ``getRuntime(``. ``->``/``::``
    are normalized to ``.`` and a leading ``new`` is dropped via the last token.
    """
    args_start = None
    for child in node.children:
        if "argument" in child.type:  # argument_list / arguments
            args_start = child.start_byte
            break
    if args_start is not None:
        text = source[node.start_byte:args_start].decode("utf-8", "replace")
    else:  # no explicit argument node (e.g. a bare command) - fall back
        text = source[node.start_byte:node.end_byte].decode("utf-8", "replace").split("(", 1)[0]
    head = text.strip().replace("->", ".").replace("::", ".")
    head = head.split()[-1] if head.split() else head  # drop a leading `new`, etc.
    return head.replace("()", "").rstrip(".")


def _enclosing_calls(call_node, source: bytes) -> list[str]:
    """Callee names of every call within the function enclosing *call_node*
    (or the whole file if the call is top-level)."""
    scope = call_node
    while scope.parent is not None and scope.type not in _FUNC_TYPES:
        scope = scope.parent
    callees: list[str] = []
    stack = [scope]
    while stack:
        n = stack.pop()
        if n.type in _CALL_TYPES:
            callees.append(_callee_text(n, source))
        stack.extend(n.children)
    # also include raw identifiers in the scope for source detection
    return callees


def _scope_text(call_node, source: bytes) -> str:
    scope = call_node
    while scope.parent is not None and scope.type not in _FUNC_TYPES:
        scope = scope.parent
    return source[scope.start_byte:scope.end_byte].decode("utf-8", "replace")


def scan_file(path: Path, root: Path) -> list[SinkHit]:
    ext = path.suffix.lower()
    spec = _TS.get(ext)
    if spec is None:
        return []
    family = spec[2]
    sink_table = sinks.SINKS.get(family, {})
    sanitizer_set = sinks.SANITIZERS.get(family, set())
    source_set = sinks.SOURCES.get(family, set())
    source_attrs = sinks.SOURCE_ATTRS.get(family, ())
    if not sink_table:
        return []
    parser = _load_parser(ext)
    if parser is None:
        return []
    try:
        source = path.read_bytes()
        tree = parser.parse(source)
    except Exception:
        return []
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name

    hits: list[SinkHit] = []
    seen: set[tuple[int, str]] = set()
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _CALL_TYPES:
            continue
        callee = _callee_text(node, source)
        if not callee:
            continue
        # Match the full dotted callee or any of its dotted suffixes, so a 2+
        # segment sink key (``Process.Start``, ``Runtime.exec``) matches a longer
        # path (``System.Diagnostics.Process.Start``) and a bare ``exec`` still hits.
        segments = callee.split(".")
        kind = next(
            (k for i in range(len(segments)) if (k := sink_table.get(".".join(segments[i:])))),
            None,
        )
        if not kind:
            continue
        line = node.start_point[0] + 1
        if (line, callee) in seen:
            continue
        seen.add((line, callee))
        scope_calls = _enclosing_calls(node, source)
        scope_src = _scope_text(node, source)
        unsanitized = not any(
            (c in sanitizer_set or c.rsplit(".", 1)[-1] in sanitizer_set)
            for c in scope_calls
        )
        input_nearby = (
            any(s in scope_src for s in source_set)
            or any(a in scope_src for a in source_attrs)
        )
        hits.append(SinkHit(
            callee=callee, kind=kind, cwe=sinks.spec(kind).cwe, file=rel,
            line=line, unsanitized=unsanitized, input_nearby=input_nearby,
        ))
    return hits


def scan_files(files: list[Path], root: Path) -> list[SinkHit]:
    hits: list[SinkHit] = []
    for path in files:
        if path.suffix.lower() in _TS:
            hits.extend(scan_file(path, root))
    return hits
