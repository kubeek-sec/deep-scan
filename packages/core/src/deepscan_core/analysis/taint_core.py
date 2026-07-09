"""Language-agnostic taint propagation core.

This module holds the parts of the taint engine that do not depend on *how* the
per-function data-flow view was built. Both the precise Python ``ast`` collector
(``taint.py``) and the generic tree-sitter collector (``ts_taint.py``) produce
:class:`FuncNode` objects and hand them to :func:`find_taint_paths`, so there is
exactly one propagation algorithm shared across every language.

Each :class:`FuncNode` carries its ``family`` (``python``, ``js``, ``go`` …); the
source / sink / sanitizer tables in :mod:`sinks` are looked up per family, so the
same traversal serves all languages without special-casing.

SAFETY: nothing here parses, imports or executes target code. Sink / source /
sanitizer names are matched as plain strings.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from . import sinks


class AnalysisAborted(Exception):
    """Raised when taint propagation is stopped before it finishes - either the
    cooperative wall-clock budget elapsed (``reason='timeout'``) or an operator
    cancelled the job (``reason='cancelled'``). Callers discard the partial run."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"taint analysis aborted ({reason})")
        self.reason = reason


@dataclass
class FuncNode:
    qualname: str
    file: str
    lineno: int
    family: str = "python"
    params: list[str] = field(default_factory=list)
    # each call: (callee, lineno, arg source-names, is_safe_sink_form, arg slots)
    # arg slots: [(position-or-kwname, names-in-that-arg)] for parameter-level sinks.
    calls: list[tuple[str, int, list[str], bool, list[tuple[object, list[str]]]]] = field(
        default_factory=list
    )
    # each assignment: (target names, RHS source names, sanitizer kinds cleared)
    assigns: list[tuple[list[str], list[str], frozenset[str]]] = field(default_factory=list)


@dataclass
class TaintPath:
    sink: str
    kind: str
    cwe: str
    file: str
    line: int
    chain: list[str]  # human-readable hops from source to sink
    family: str = "python"
    # "high" when the sink-bearing function reads an explicit untrusted source;
    # "medium" when the tainted value only entered as a (assumed-untrusted)
    # parameter. The engine can raise a "medium" to "high" from reachability.
    confidence: str = "medium"
    # Triage breadcrumbs (Pysa-style), merged into the finding's extra.
    features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "sink": self.sink, "kind": self.kind, "cwe": self.cwe,
            "file": self.file, "line": self.line, "chain": self.chain,
            "family": self.family, "confidence": self.confidence,
            "features": self.features,
            "remediation": sinks.remediation(self.kind),
        }


# Cross-function descent is capped at this many hops. A sink only reachable by a
# deeper unique chain is still reported - the outer loop processes every function
# as its own entry point (taint is seeded from its parameters, context-insensitively),
# so coverage is unchanged; the cap only bounds chain length (and thus the cost of
# copying it) and keeps reported provenance readable on pathologically deep graphs.
_MAX_CHAIN_HOPS = 64


_NO_KINDS: frozenset[str] = frozenset()


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _san_of(sanitized_for: dict[str, set[str]], name: str):
    """Kinds already cleared for *name* (or its receiver head)."""
    return sanitized_for.get(name) or sanitized_for.get(name.split(".")[0]) or _NO_KINDS


def _in_slot(name: str, slots: list[tuple[object, list[str]]], dangerous: frozenset) -> bool:
    """True when *name* appears in one of the sink's *dangerous* argument slots."""
    return any(pos in dangerous and name in names for pos, names in slots)


def _resolve(callee: str, caller: FuncNode, funcs: dict[str, FuncNode]) -> FuncNode | None:
    """Resolve a callee name to a local function definition.

    Candidates are restricted to the caller's own language family, so a helper
    named ``run``/``exec`` in one language can never resolve into a same-named
    function from another language sharing the corpus. Within a family, a unique
    same-file match wins; otherwise a single global match is used.
    """
    short = _short(callee)
    matches = [
        f for f in funcs.values()
        if _short(f.qualname) == short and f.family == caller.family
    ]
    if not matches:
        return None
    same_file = [f for f in matches if f.file == caller.file]
    if len(same_file) == 1:
        return same_file[0]
    return matches[0] if len(matches) == 1 else None


def find_taint_paths(
    funcs: dict[str, FuncNode],
    *,
    deadline: float | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> list[TaintPath]:
    """Trace source → sink paths, following calls into local functions and
    propagating taint through their parameters.

    Source / sink / sanitizer tables are selected per ``fn.family`` so a single
    traversal works for every language.

    Two cooperative bounds keep this whole-program pass from pegging a core
    indefinitely on a large/dense graph (the engine is CPU-bound and runs in a
    worker thread that cannot be killed from outside):

    * ``deadline`` - a ``time.monotonic()`` value past which the run raises
      :class:`AnalysisAborted` (``reason='timeout'``);
    * ``should_stop`` - a callback polled during the walk; when it returns true
      the run raises :class:`AnalysisAborted` (``reason='cancelled'``).
    """
    paths: list[TaintPath] = []

    # Index functions by *short* (unqualified) name so resolving a callee is O(1)
    # average instead of an O(N) scan of every function on every call site - the
    # difference between seconds and hours once the graph spans a whole large
    # codebase (e.g. a multi-thousand-file C corpus).
    by_short: dict[str, list[FuncNode]] = {}
    for f in funcs.values():
        by_short.setdefault(_short(f.qualname), []).append(f)

    def resolve(callee: str, caller: FuncNode) -> FuncNode | None:
        cands = by_short.get(_short(callee))
        if not cands:
            return None
        fam = [f for f in cands if f.family == caller.family]
        if not fam:
            return None
        same_file = [f for f in fam if f.file == caller.file]
        if len(same_file) == 1:
            return same_file[0]
        return fam[0] if len(fam) == 1 else None

    def check_abort() -> None:
        if should_stop is not None and should_stop():
            raise AnalysisAborted("cancelled")
        if deadline is not None and time.monotonic() > deadline:
            raise AnalysisAborted("timeout")

    def process(fn: FuncNode, chain: list[str]) -> list[tuple[FuncNode, list[str]]]:
        """Emit fn's sink findings (seeding taint from its parameters) and return
        the resolvable, tainted-arg callees to descend into."""
        fam = fn.family
        src_calls = sinks.SOURCES.get(fam, set())
        src_shorts = {_short(s) for s in src_calls}
        src_attrs = sinks.SOURCE_ATTRS.get(fam, ())
        snk = sinks.SINKS.get(fam, {})
        san = sinks.SANITIZERS.get(fam, {})
        sink_args = sinks.SINK_ARGS.get(fam, {})

        # Confidence basis: does the sink-bearing function itself read an
        # explicit untrusted source (request.*, getenv, argv, input …)? If so a
        # tainted value really is untrusted (high). If the data only arrives as a
        # parameter, the untrustedness is an assumption (medium) until call-graph
        # reachability confirms exposure. Order-independent, so it is stable
        # whichever way the context-insensitive walk reaches this function.
        has_local_source = any(
            c in src_calls or _short(c) in src_shorts or any(s in c for s in src_attrs)
            for c, _l, _a, _sf, _sl in fn.calls
        )
        confidence = "high" if has_local_source else "medium"

        # Entry assumption: every parameter is a potential untrusted source
        # (HTTP handlers, CLI entry points, exported helpers, …). ``sanitized_for``
        # remembers, per tainted name, which vuln kinds were already neutralised -
        # so a value cleared for one class (``html.escape`` ⇒ xss) still trips a
        # sink of another class (sql), instead of being dropped wholesale.
        local = set(fn.params)
        sanitized_for: dict[str, set[str]] = {}
        changed = True
        while changed:
            changed = False
            for targets, rhs, san_kinds in fn.assigns:
                tainted_ops = [r for r in rhs if r in local or r.split(".")[0] in local]
                if not tainted_ops:
                    continue
                # A kind carries to the target only if *every* tainted operand was
                # already cleared for it; plus the kinds this assignment's own
                # sanitizer call clears.
                carried = set(_san_of(sanitized_for, tainted_ops[0]))
                for r in tainted_ops[1:]:
                    carried &= _san_of(sanitized_for, r)
                eff = san_kinds | carried
                for t in targets:
                    if t not in local:
                        local.add(t)
                        changed = True
                    if eff:
                        prev = sanitized_for.get(t)
                        merged = prev | eff if prev else set(eff)
                        if merged != prev:
                            sanitized_for[t] = merged
                            changed = True
        descend: list[tuple[FuncNode, list[str]]] = []
        for callee, line, args, safe_form, slots in fn.calls:
            short = _short(callee)
            tainted_args = [a for a in args if a in local or a.split(".")[0] in local]
            if callee in src_calls or short in src_shorts \
                    or any(s in callee for s in src_attrs):
                local.add(f"__ret_{line}")
            san_here = san.get(callee) or san.get(short)
            if san_here is not None and tainted_args:
                # bare ``sanitize(x)`` statement: tag its args' cleared kinds
                for a in tainted_args:
                    sanitized_for.setdefault(a, set()).update(san_here)
                continue
            kind = snk.get(callee) or snk.get(short)
            if kind and not safe_form and tainted_args:
                # only the args not already sanitized *for this kind* are live.
                live = [a for a in tainted_args if kind not in _san_of(sanitized_for, a)]
                # parameter-level sinks: restrict to the dangerous argument slot(s).
                dangerous = sink_args.get(callee, sink_args.get(short))
                if dangerous is not None and live:
                    live = [a for a in live if _in_slot(a, slots, dangerous)]
                if live:
                    hop = chain + [
                        f"{fn.file}:{fn.qualname} → {callee}() at line {line} "
                        f"[tainted: {', '.join(sorted(set(live)))}]"
                    ]
                    paths.append(TaintPath(
                        sink=callee, kind=kind, cwe=sinks.spec(kind).cwe,
                        file=fn.file, line=line, chain=hop, family=fam,
                        confidence=confidence,
                        features={
                            "source_evidence": "explicit" if has_local_source else "parameter",
                            "cross_function": bool(chain),
                            "hops": len(chain),
                            # a sibling arg was cleared for a *different* kind.
                            "sanitized_other_kind": len(live) < len(tainted_args),
                        },
                    ))
            callee_fn = resolve(callee, fn)
            if callee_fn and tainted_args:
                descend.append(
                    (callee_fn, chain + [f"{fn.file}:{fn.qualname} → {callee}() at line {line}"])
                )
        return descend

    # Walk each function at most once for the whole run. The tainted set entering
    # any function is always exactly its own parameters (a callee is seeded with
    # ``set(callee.params)``, never the caller's tainted args), so a function's
    # findings are fully determined by its identity - re-reaching it by another
    # path only re-derives the same (file, line, sink) sinks, which the final
    # dedup collapses anyway. A single global guard therefore preserves every
    # finding while collapsing a combinatorial path explosion into O(functions)
    # work. The traversal is an explicit stack (not recursion) so a deep call
    # chain over a large codebase can't overflow Python's recursion limit.
    explored: set[str] = set()
    for root in funcs.values():
        check_abort()
        if f"{root.file}::{root.qualname}" in explored:
            continue
        stack: list[tuple[FuncNode, list[str]]] = [(root, [])]
        while stack:
            fn, chain = stack.pop()
            node_key = f"{fn.file}::{fn.qualname}"
            if node_key in explored:
                continue
            explored.add(node_key)
            check_abort()
            if len(chain) >= _MAX_CHAIN_HOPS:
                # Stop descending; any callee not yet seen is still covered when
                # the outer loop reaches it as its own entry point.
                process(fn, chain)
                continue
            for callee_fn, new_chain in process(fn, chain):
                if f"{callee_fn.file}::{callee_fn.qualname}" not in explored:
                    stack.append((callee_fn, new_chain))
    unique: dict[tuple, TaintPath] = {}
    for p in paths:
        unique[(p.file, p.line, p.sink)] = p
    return list(unique.values())
