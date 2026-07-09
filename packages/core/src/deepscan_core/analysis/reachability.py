"""Call-graph reachability over the graphoofy code graph.

Answers, for a finding at ``file:line``: is the enclosing function reachable
from an **entry point** (a function the outside world can invoke - an HTTP
handler, a CLI ``main``, an exported/uncalled function), and by what call path?
That turns a raw sink into evidence about whether untrusted input can actually
get there.

It works for every language graphoofy extracts, because it consumes graphoofy's
own function nodes and ``calls`` edges. The signal is only as complete as that
extraction (conservative: missing call edges make a function look like an entry
point rather than inventing reachability), so it is reported as supporting
evidence, not proof.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

# Function names that strongly indicate an externally-invoked entry point.
_WEB_HANDLER_RE = re.compile(
    r"(^|_)(handler|handle|view|route|get|post|put|delete|patch|index|dispatch|"
    r"do_[a-z]+|on_[a-z]+|login|logout|callback|webhook|endpoint|resolve|"
    r"lambda_handler)($|_|\b)",
    re.IGNORECASE,
)
_CLI_RE = re.compile(r"^(main|run|cli|__main__|cmd_[a-z]+|execute)$", re.IGNORECASE)


@dataclass
class ReachInfo:
    reachable: bool
    entry_point: str | None  # label of the entry function the path starts from
    entry_kind: str          # "web" | "cli" | "exported" | "internal" | "unknown"
    distance: int            # hops from the entry point (0 = is the entry point)
    call_path: list[str] = field(default_factory=list)  # entry → … → enclosing fn


@dataclass
class _Func:
    node_id: str
    label: str
    file: str
    line: int


def _line_of(loc: str | None) -> int:
    if not loc:
        return 0
    m = re.search(r"\d+", str(loc))
    return int(m.group()) if m else 0


def _is_function_node(node: dict) -> bool:
    label = str(node.get("label") or "")
    return label.endswith("()")


def _entry_kind(label: str) -> str:
    name = label[:-2] if label.endswith("()") else label  # strip "()"
    name = name.rsplit(".", 1)[-1]                          # drop a Class. prefix
    if _CLI_RE.match(name):
        return "cli"
    if _WEB_HANDLER_RE.search(name):
        return "web"
    return "exported"


class CallGraph:
    """Function-level call graph built from a graphoofy extraction dict."""

    def __init__(self, extraction: dict):
        self._funcs: dict[str, _Func] = {}
        self._by_file: dict[str, list[_Func]] = {}
        self._calls: dict[str, set[str]] = {}     # caller -> callees
        self._called: dict[str, set[str]] = {}    # callee -> callers
        self._reach: dict[str, ReachInfo] = {}

        for node in extraction.get("nodes", []):
            if not isinstance(node, dict) or not _is_function_node(node):
                continue
            nid = node.get("id")
            if not nid:
                continue
            fn = _Func(
                node_id=nid,
                label=str(node.get("label") or nid),
                file=str(node.get("source_file") or ""),
                line=_line_of(node.get("source_location")),
            )
            self._funcs[nid] = fn
            self._by_file.setdefault(fn.file, []).append(fn)

        for edge in extraction.get("edges", []):
            if not isinstance(edge, dict) or edge.get("relation") != "calls":
                continue
            src, dst = edge.get("source"), edge.get("target")
            if src in self._funcs and dst in self._funcs:
                self._calls.setdefault(src, set()).add(dst)
                self._called.setdefault(dst, set()).add(src)

        for fns in self._by_file.values():
            fns.sort(key=lambda f: f.line)
        self._compute()

    # -- entry points + BFS ------------------------------------------------- #

    def _entry_points(self) -> list[str]:
        entries = []
        for nid, fn in self._funcs.items():
            name = fn.label
            no_caller = not self._called.get(nid)
            if no_caller or _entry_kind(name) in ("web", "cli"):
                entries.append(nid)
        return entries

    def _compute(self) -> None:
        # Multi-source BFS; for each function record the nearest entry, the
        # number of hops and the call path from that entry.
        parent: dict[str, str | None] = {}
        root: dict[str, str] = {}
        dist: dict[str, int] = {}
        q: deque[str] = deque()
        for e in self._entry_points():
            parent[e] = None
            root[e] = e
            dist[e] = 0
            q.append(e)
        while q:
            cur = q.popleft()
            for callee in self._calls.get(cur, ()):  # forward call edges
                if callee not in dist:
                    parent[callee] = cur
                    root[callee] = root[cur]
                    dist[callee] = dist[cur] + 1
                    q.append(callee)

        for nid, fn in self._funcs.items():
            if nid in dist:
                path = self._path(nid, parent)
                entry_id = root[nid]
                self._reach[nid] = ReachInfo(
                    reachable=True,
                    entry_point=self._funcs[entry_id].label,
                    entry_kind=_entry_kind(self._funcs[entry_id].label),
                    distance=dist[nid],
                    call_path=path,
                )
            else:
                self._reach[nid] = ReachInfo(
                    reachable=False, entry_point=None, entry_kind="internal", distance=-1
                )

    def _path(self, nid: str, parent: dict[str, str | None]) -> list[str]:
        chain: list[str] = []
        cur: str | None = nid
        seen: set[str] = set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            chain.append(self._funcs[cur].label)
            cur = parent.get(cur)
        chain.reverse()  # entry → … → enclosing function
        return chain

    # -- lookup ------------------------------------------------------------- #

    def _enclosing(self, file: str, line: int) -> _Func | None:
        # Match the finding's (root-relative) path against graphoofy's
        # source_file by suffix, then pick the function whose definition line is
        # the greatest <= the finding line.
        candidates: list[_Func] = []
        for src_file, fns in self._by_file.items():
            if src_file.endswith(file) or file.endswith(src_file):
                candidates.extend(fns)
        enclosing = [f for f in candidates if 0 < f.line <= line]
        if not enclosing:
            return None
        return max(enclosing, key=lambda f: f.line)

    def lookup(self, file: str, line: int) -> ReachInfo | None:
        fn = self._enclosing(file, line)
        if fn is None:
            return None
        return self._reach.get(fn.node_id)

    def enclosing_id(self, file: str, line: int) -> str | None:
        """Node id of the function enclosing *file:line*, or None."""
        fn = self._enclosing(file, line)
        return fn.node_id if fn else None

    def func_meta(self, node_id: str) -> dict | None:
        """``{"label", "file", "line", "location"}`` for a function node."""
        fn = self._funcs.get(node_id)
        if fn is None:
            return None
        return {
            "label": fn.label, "file": fn.file, "line": fn.line,
            "location": f"{fn.file}:{fn.line}" if fn.file else fn.label,
        }

    def entry_point_ids(self) -> list[str]:
        """Function nodes that look externally-invocable (no in-repo caller or a
        handler/main name) - the roots of attack paths."""
        return self._entry_points()

    def reachable_files(self) -> set[str]:
        """Source files containing at least one function reachable from an entry
        point."""
        out: set[str] = set()
        for nid, info in self._reach.items():
            if info.reachable:
                fn = self._funcs.get(nid)
                if fn and fn.file:
                    out.add(fn.file)
        return out

    def call_digraph(self):
        """A NetworkX DiGraph of function nodes + ``calls`` edges (for dominator
        / centrality analysis). Built lazily so importing this module is cheap."""
        import networkx as nx

        G = nx.DiGraph()
        G.add_nodes_from(self._funcs)
        for caller, callees in self._calls.items():
            for callee in callees:
                G.add_edge(caller, callee)
        return G

    # -- summary ------------------------------------------------------------ #

    @property
    def entry_point_count(self) -> int:
        return sum(1 for r in self._reach.values() if r.distance == 0)

    @property
    def function_count(self) -> int:
        return len(self._funcs)
