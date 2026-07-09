"""Generic tree-sitter taint analysis for the non-Python languages.

Mirrors the precise Python engine (:mod:`taint`) for every other installed
grammar family (js/ts, java, go, ruby, php, c#, rust, c/cpp). It builds the same
per-function data-flow view - parameters as taint entry points, calls with their
argument source-names, assignments with target/RHS names and a sanitizer flag -
directly from the tree-sitter parse tree, then hands it to the shared, language-
agnostic :func:`taint_core.find_taint_paths`. So all languages run one
propagation algorithm and produce identical, high-confidence source→sink paths.

Per-language differences (which node types are functions, calls, assignments,
identifiers, member-access) are captured in a single :data:`_LANG` table; the
walk itself is language-neutral.

SAFETY: files are parsed with tree-sitter only - never imported or executed.
Sink / source / sanitizer names are matched as strings.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from pathlib import Path

from . import sinks
from .taint_core import FuncNode, TaintPath, find_taint_paths

# extension → (tree-sitter module, language-function name, kb family). Python is
# excluded on purpose: it keeps its precise ``ast`` engine.
_TS: dict[str, tuple[str, str, str]] = {
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

# Call/construction node types across grammars (a superset safety net on top of
# each language's own ``call_types``).
_CALL_TYPES = frozenset({
    "call", "call_expression", "method_invocation", "function_call_expression",
    "member_call_expression", "scoped_call_expression", "invocation_expression",
    "object_creation_expression", "new_expression", "macro_invocation",
    "method_call", "command", "command_call", "nullsafe_member_call_expression",
})


@dataclass(frozen=True)
class TaintLangConfig:
    func_types: frozenset[str]            # function/method definitions
    param_container_types: frozenset[str] # the parameter-list wrapper node
    param_decl_types: frozenset[str]      # per-param wrapper ({} ⇒ bare-identifier params)
    call_types: frozenset[str]
    assign_types: frozenset[str]          # plain assignment + variable-declaration nodes
    aug_assign_types: frozenset[str]      # dedicated x+=y nodes (where the grammar has them)
    ident_types: frozenset[str]           # leaf name nodes - emitted, never descended
    member_types: frozenset[str]          # dotted-access nodes - flattened + receiver descended


_LANG: dict[str, TaintLangConfig] = {
    "js": TaintLangConfig(
        func_types=frozenset({
            "function_declaration", "function_expression", "arrow_function",
            "method_definition", "generator_function", "generator_function_declaration",
        }),
        param_container_types=frozenset({"formal_parameters"}),
        param_decl_types=frozenset({
            "required_parameter", "optional_parameter", "rest_pattern",
            "assignment_pattern", "object_pattern", "array_pattern",
        }),
        call_types=frozenset({"call_expression", "new_expression"}),
        assign_types=frozenset({"variable_declarator", "assignment_expression"}),
        aug_assign_types=frozenset({"augmented_assignment_expression"}),
        ident_types=frozenset({
            "identifier", "shorthand_property_identifier", "property_identifier",
        }),
        member_types=frozenset({"member_expression", "subscript_expression"}),
    ),
    "java": TaintLangConfig(
        func_types=frozenset({"method_declaration", "constructor_declaration"}),
        param_container_types=frozenset({"formal_parameters"}),
        param_decl_types=frozenset({"formal_parameter", "spread_parameter"}),
        call_types=frozenset({"method_invocation", "object_creation_expression"}),
        assign_types=frozenset({"variable_declarator", "assignment_expression"}),
        aug_assign_types=frozenset(),  # += is operator-based on assignment_expression
        ident_types=frozenset({"identifier"}),
        member_types=frozenset({"field_access", "scoped_identifier"}),
    ),
    "go": TaintLangConfig(
        func_types=frozenset({"function_declaration", "method_declaration", "func_literal"}),
        param_container_types=frozenset({"parameter_list"}),
        param_decl_types=frozenset({"parameter_declaration", "variadic_parameter_declaration"}),
        call_types=frozenset({"call_expression"}),
        assign_types=frozenset({"short_var_declaration", "var_spec", "assignment_statement"}),
        aug_assign_types=frozenset(),  # += is operator-based on assignment_statement
        ident_types=frozenset({"identifier", "field_identifier", "package_identifier"}),
        member_types=frozenset({"selector_expression"}),
    ),
    "ruby": TaintLangConfig(
        func_types=frozenset({"method", "singleton_method"}),
        param_container_types=frozenset({"method_parameters", "parameters", "block_parameters"}),
        param_decl_types=frozenset({
            "optional_parameter", "keyword_parameter", "splat_parameter",
            "hash_splat_parameter",
        }),
        call_types=frozenset({"call", "command", "command_call", "method_call"}),
        assign_types=frozenset({"assignment"}),
        aug_assign_types=frozenset({"operator_assignment"}),
        ident_types=frozenset({"identifier", "instance_variable", "global_variable", "constant"}),
        member_types=frozenset(),  # Ruby dotted access parses as a `call`
    ),
    "php": TaintLangConfig(
        func_types=frozenset({"function_definition", "method_declaration"}),
        param_container_types=frozenset({"formal_parameters"}),
        param_decl_types=frozenset({
            "simple_parameter", "variadic_parameter", "property_promotion_parameter",
        }),
        call_types=frozenset({
            "function_call_expression", "member_call_expression",
            "scoped_call_expression", "object_creation_expression",
            "nullsafe_member_call_expression",
        }),
        assign_types=frozenset({"assignment_expression"}),
        aug_assign_types=frozenset({"augmented_assignment_expression"}),
        ident_types=frozenset({"variable_name", "name"}),  # variable_name keeps '$'
        member_types=frozenset({
            "member_access_expression", "scoped_property_access_expression",
            "subscript_expression",
        }),
    ),
    "csharp": TaintLangConfig(
        func_types=frozenset({
            "method_declaration", "constructor_declaration", "local_function_statement",
        }),
        param_container_types=frozenset({"parameter_list"}),
        param_decl_types=frozenset({"parameter"}),
        call_types=frozenset({"invocation_expression", "object_creation_expression"}),
        assign_types=frozenset({"variable_declarator", "assignment_expression"}),
        aug_assign_types=frozenset(),  # += is operator-based on assignment_expression
        ident_types=frozenset({"identifier"}),
        member_types=frozenset({"member_access_expression"}),
    ),
    "rust": TaintLangConfig(
        func_types=frozenset({"function_item"}),
        param_container_types=frozenset({"parameters"}),
        param_decl_types=frozenset({"parameter"}),  # self_parameter naturally excluded
        call_types=frozenset({"call_expression", "macro_invocation"}),
        assign_types=frozenset({"let_declaration", "assignment_expression"}),
        aug_assign_types=frozenset({"compound_assignment_expr"}),
        ident_types=frozenset({"identifier", "field_identifier"}),
        member_types=frozenset({"field_expression", "scoped_identifier"}),
    ),
    "c": TaintLangConfig(  # also C++ (family "c")
        func_types=frozenset({"function_definition"}),
        param_container_types=frozenset({"parameter_list"}),
        param_decl_types=frozenset({"parameter_declaration"}),
        call_types=frozenset({"call_expression", "new_expression"}),
        assign_types=frozenset({"init_declarator", "assignment_expression"}),
        aug_assign_types=frozenset(),  # += is operator-based on assignment_expression
        ident_types=frozenset({"identifier", "field_identifier"}),
        member_types=frozenset({"field_expression", "qualified_identifier"}),
    ),
}

_parser_cache: dict[str, object] = {}


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


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _callee_text(node, source: bytes) -> str:
    """Callee string of a call node: the text up to its argument list.

    ``->``/``::`` are normalized to ``.`` and a leading ``new`` is dropped via
    the last token, so ``new SqlCommand(x)`` → ``SqlCommand`` and
    ``Runtime.getRuntime().exec(x)`` → ``Runtime.getRuntime.exec`` (whose ``exec``
    suffix matches a sink key).
    """
    args_start = None
    for child in node.children:
        if "argument" in child.type:  # argument_list / arguments
            args_start = child.start_byte
            break
    if args_start is not None:
        text = source[node.start_byte:args_start].decode("utf-8", "replace")
    else:  # no explicit argument node - fall back to the head before "("
        text = _text(node, source).split("(", 1)[0]
    head = text.strip().replace("->", ".").replace("::", ".")
    head = head.split()[-1] if head.split() else head  # drop a leading `new`, etc.
    return head.replace("()", "").rstrip(".")


def _flatten(node, source: bytes) -> str:
    """Member-access node → dotted form, normalized like :func:`_callee_text`."""
    return _text(node, source).replace("->", ".").replace("::", ".").replace("()", "").strip()


def _subtree_names(node, cfg: TaintLangConfig, source: bytes) -> list[str]:
    """Source-names referenced in *node* - leaf identifiers plus dotted member
    forms and their receiver heads (mirrors ``taint._names_in``: ``a.b.c`` →
    ``{a.b.c, a.b, a}``, never the trailing ``b``/``c`` alone). Identifier nodes
    are emitted by raw text and never descended, so PHP ``$x`` / Ruby ``@x``
    prefixes survive intact.
    """
    out: list[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in cfg.ident_types:
            out.append(_text(n, source))
        elif n.type in cfg.member_types:
            out.append(_flatten(n, source))
            kids = n.named_children
            if kids:  # descend only into the receiver, not the trailing property
                stack.append(kids[0])
        else:
            stack.extend(n.children)
    return out


def _last_ident(node, cfg: TaintLangConfig, source: bytes) -> str | None:
    """Last identifier in *node* in pre-order (used to reach a C declarator name)."""
    found: list[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in cfg.ident_types or n.type == "variable_name":
            found.append(_text(n, source))
        stack.extend(reversed(n.children))
    return found[-1] if found else None


def _decl_func_name(node, source: bytes) -> str:
    """Descend a C/C++ declarator chain to the function's name identifier."""
    cur = node
    for _ in range(8):
        if cur is None:
            break
        if cur.type in ("identifier", "field_identifier", "qualified_identifier",
                        "destructor_name", "operator_name", "type_identifier"):
            return _text(cur, source)
        nxt = cur.child_by_field_name("declarator")
        if nxt is None:
            for c in cur.named_children:
                if c.type in ("identifier", "field_identifier", "qualified_identifier"):
                    return _text(c, source)
            break
        cur = nxt
    return ""


def _func_name(node, cfg: TaintLangConfig, source: bytes) -> str:
    nm = node.child_by_field_name("name")
    if nm is not None:
        return _text(nm, source)
    decl = node.child_by_field_name("declarator")
    if decl is not None:
        name = _decl_func_name(decl, source)
        if name:
            return name
    for c in node.named_children:
        if c.type in cfg.ident_types:
            return _text(c, source)
    return "<anon>"


def _find_param_container(func_node, cfg: TaintLangConfig):
    pc = func_node.child_by_field_name("parameters")
    if pc is not None:
        return pc
    for c in func_node.named_children:  # C: params live under function_declarator
        if c.type in cfg.param_container_types:
            return c
        for g in c.named_children:
            if g.type in cfg.param_container_types:
                return g
    return None


def _param_names(func_node, cfg: TaintLangConfig, source: bytes) -> list[str]:
    cont = _find_param_container(func_node, cfg)
    if cont is None:
        return []
    names: list[str] = []
    for p in cont.named_children:
        if p.type in cfg.ident_types:  # bare-identifier param (JS/Ruby/Go)
            names.append(_text(p, source))
            continue
        if cfg.param_decl_types and p.type not in cfg.param_decl_types:
            continue  # skip self_parameter, commas, type-only entries, etc.
        nm = p.child_by_field_name("name") or p.child_by_field_name("pattern")
        if nm is not None:
            names.append(_text(nm, source))
        else:  # C-style: descend the declarator chain to the inner identifier
            decl = p.child_by_field_name("declarator") or p
            last = _last_ident(decl, cfg, source)
            if last:
                names.append(last)
    return [n for n in names if n]


# ---- safe-form recognition (conservative; default = flag) ------------------- #

_SHELL_RE = re.compile(r"shell\s*[:=]\s*[Tt]rue")
_NON_COMPOUND_OPS = frozenset({"=", "==", "===", "!=", "<=", ">=", ":=", "=>"})
_SQL_SHORTS = frozenset({
    "execute", "executemany", "query", "raw", "exec", "queryrow",
    "executequery", "executeupdate", "executereader", "executenonquery",
    "find_by_sql", "exec_query", "sql_query", "sqlcommand", "preparestatement",
})
_EXEC_SHORTS = frozenset({
    "run", "call", "popen", "spawn", "spawnsync", "execfile", "command",
    "start", "exec", "check_output", "check_call", "new",
})
_LIST_LITERAL_TYPES = frozenset({
    "array", "list", "array_creation_expression", "composite_literal",
    "slice_literal", "array_expression", "collection_expression",
    "array_literal", "list_literal",
})
_STRING_LITERAL_TYPES = frozenset({
    "string", "interpreted_string_literal", "string_literal",
    "raw_string_literal", "encapsed_string",
})


def _is_string_inert_child(node_type: str) -> bool:
    """A named string child that does NOT introduce interpolation.

    Grammars name the literal content differently (``string_content``,
    ``interpreted_string_literal_content``, ``string_fragment`` …), so match by
    shape; anything else named (template substitution, a PHP ``variable_name``
    inside ``"$x"``, a Ruby ``interpolation``) means the string is not constant.
    """
    return (
        node_type.endswith("content")
        or node_type.endswith("fragment")
        or node_type == "escape_sequence"
        or node_type in ("string_start", "string_end")
    )


def _is_plain_string_literal(node) -> bool:
    """A constant string with no interpolation/embedded expression."""
    if node is None or node.type not in _STRING_LITERAL_TYPES:
        return False
    for c in node.children:
        if c.is_named and not _is_string_inert_child(c.type):
            return False  # e.g. template substitution, PHP variable in "$x"
    return True


def _op_is_compound(node, source: bytes) -> bool:
    """True when an assignment node's operator is compound (``+=`` etc.), for
    grammars that reuse one assignment node type for plain and augmented forms."""
    for c in node.children:
        if c.is_named:
            continue
        t = _text(c, source).strip()
        if t.endswith("=") and t not in _NON_COMPOUND_OPS:
            return True
    return False


def _is_safe_sink_call_ts(callee: str, family: str, arg_nodes: list, call_node, source: bytes) -> bool:
    """Recognise structurally-proven-safe call shapes so patched code is not
    flagged. Conservative: returns True only when the shape itself rules out
    injection; otherwise flags."""
    short = callee.rsplit(".", 1)[-1].lower()
    call_src = _text(call_node, source)
    if _SHELL_RE.search(call_src):
        return False  # an explicit shell flag vetoes every safe verdict
    if short in _SQL_SHORTS and arg_nodes:
        # constant/parameterized query: the query text is a plain string literal,
        # so any further args are bound out-of-band.
        if _is_plain_string_literal(arg_nodes[0]):
            return True
    if short in _EXEC_SHORTS and arg_nodes:
        # exec given an argument *list* (no shell) cannot be a shell-injection.
        if arg_nodes[0].type in _LIST_LITERAL_TYPES:
            return True
    return False


def _rhs_sanitizer_kinds(value, family: str, cfg: TaintLangConfig, source: bytes) -> frozenset[str]:
    """Vuln *kinds* neutralised by sanitizer call(s) on this RHS (empty if none)."""
    san = sinks.SANITIZERS.get(family, {})
    if not san or value is None:
        return frozenset()
    kinds: set[str] = set()
    stack = [value]
    while stack:
        n = stack.pop()
        if n.type in cfg.call_types or n.type in _CALL_TYPES:
            callee = _callee_text(n, source)
            k = san.get(callee) or san.get(callee.rsplit(".", 1)[-1])
            if k:
                kinds |= k
        stack.extend(n.children)
    return frozenset(kinds)


# ---- per-file collection ---------------------------------------------------- #

class _FileCollector:
    def __init__(self, cfg: TaintLangConfig, family: str, source: bytes, rel: str):
        self.cfg = cfg
        self.family = family
        self.source = source
        self.rel = rel
        self.funcs: dict[str, FuncNode] = {}

    def collect(self, root) -> None:
        """Iteratively find every function node, build its FuncNode, and collect
        its body - descending through non-function nodes to reach nested funcs."""
        stack = [(root, ())]
        while stack:
            node, names = stack.pop()
            for child in node.children:
                if child.type in self.cfg.func_types:
                    name = _func_name(child, self.cfg, self.source)
                    qual = ".".join((*names, name))
                    fn = FuncNode(
                        qualname=qual, file=self.rel,
                        lineno=child.start_point[0] + 1, family=self.family,
                        params=_param_names(child, self.cfg, self.source),
                    )
                    self.funcs[qual] = fn
                    self._collect_body(child, fn)
                    stack.append((child, (*names, name)))
                else:
                    stack.append((child, names))

    def _collect_body(self, func_node, fn: FuncNode) -> None:
        cfg = self.cfg
        stack = list(func_node.children)
        while stack:
            n = stack.pop()
            if n.type in cfg.func_types:
                continue  # a nested function gets its own FuncNode
            if n.type in cfg.call_types or n.type in _CALL_TYPES:
                self._record_call(n, fn)
            if n.type in cfg.assign_types or n.type in cfg.aug_assign_types:
                self._record_assign(n, fn)
            stack.extend(n.children)

    def _record_call(self, node, fn: FuncNode) -> None:
        callee = _callee_text(node, self.source)
        if not callee:
            return
        args_node = None
        for c in node.children:
            if "argument" in c.type:
                args_node = c
                break
        arg_names: list[str] = []
        arg_nodes: list = []
        slots: list[tuple[object, list[str]]] = []
        if args_node is not None:
            for i, a in enumerate(args_node.named_children):
                real = a
                if a.type == "argument":  # PHP wraps each arg in an `argument`
                    kids = a.named_children
                    real = kids[0] if kids else a
                names = _subtree_names(real, self.cfg, self.source)
                arg_names.extend(names)
                arg_nodes.append(real)
                slots.append((i, names))
        line = node.start_point[0] + 1
        safe = _is_safe_sink_call_ts(callee, self.family, arg_nodes, node, self.source)
        fn.calls.append((callee, line, arg_names, safe, slots))

    def _record_assign(self, node, fn: FuncNode) -> None:
        cfg = self.cfg
        src = self.source
        named = node.named_children
        tgt = (node.child_by_field_name("left")
               or node.child_by_field_name("name")
               or node.child_by_field_name("pattern"))
        if tgt is None:
            tgt = named[0] if named else None
        val = node.child_by_field_name("right") or node.child_by_field_name("value")
        if val is None:
            for c in reversed(named):
                if c is not tgt:
                    val = c
                    break
        if tgt is None:
            return
        targets = _subtree_names(tgt, cfg, src)
        if not targets:
            return
        rhs = _subtree_names(val, cfg, src) if val is not None else []
        if node.type in cfg.aug_assign_types or _op_is_compound(node, src):
            rhs = rhs + targets  # x += y keeps x's prior taint
        san_kinds = _rhs_sanitizer_kinds(val, self.family, cfg, src)
        fn.assigns.append((targets, rhs, san_kinds))


def build_graph(files: list[Path], root: Path) -> dict[str, FuncNode]:
    """Build the cross-file FuncNode graph for every non-Python supported file."""
    funcs: dict[str, FuncNode] = {}
    for path in files:
        ext = path.suffix.lower()
        spec = _TS.get(ext)
        if spec is None:
            continue
        cfg = _LANG.get(spec[2])
        if cfg is None:
            continue
        parser = _load_parser(ext)
        if parser is None:
            continue
        try:
            source = path.read_bytes()
            tree = parser.parse(source)
        except Exception:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        collector = _FileCollector(cfg, spec[2], source, rel)
        try:
            collector.collect(tree.root_node)
        except Exception:
            continue
        # Key by file + qualname so same-named functions in different files
        # (e.g. a vulnerable file and its *_patched sibling) do not collide.
        for qual, fn in collector.funcs.items():
            funcs[f"{rel}::{qual}"] = fn
    return funcs


def analyze_ts(
    files: list[Path],
    root: Path,
    *,
    deadline: float | None = None,
    should_stop=None,
) -> list[TaintPath]:
    """Build the graph for the non-Python supported files and return taint paths."""
    funcs = build_graph(files, root)
    if not funcs:
        return []
    return find_taint_paths(funcs, deadline=deadline, should_stop=should_stop)
