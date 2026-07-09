"""Query the security graph payload for precise AppSec questions.

Answers the questions in ``docs/graph`` from the payload produced by
:mod:`graph_view` (precomputed layer sets/paths + node tags/metrics), resolving
node ids to readable ``{label, location}``. Most questions are precomputed;
``blast_radius`` is parameterized by a target component and computed on demand.

Used by the MCP ``query_graph`` tool and reusable from the skill / CLI.
"""

from __future__ import annotations

from collections import deque
from typing import Any

# question key → (human label, layer key or "blast_radius")
QUESTIONS: dict[str, str] = {
    "unsanitized_sources": "Which sources are unsanitized?",
    "critical_functions": "Which functions are the most critical?",
    "endpoints_reach_sink": "Which endpoints reach a sink?",
    "endpoints_reach_taint": "Which endpoints reach a taint?",
    "shortest_paths_critical": "What are the shortest paths that access a critical function?",
    "all_paths_critical": "What are all the possible paths to reach critical functions?",
    "external_dependencies": "What are the external dependencies used in the application?",
    "vulnerable_deps_reach_critical": "Which external dependencies, if vulnerable, could reach a critical function?",
    "attack_paths": "Which attack paths could impact hard?",
    "blast_radius": "What is the blast radius of a compromised component?",
}

# question key → payload.layers key (blast_radius is special)
_LAYER = {
    "unsanitized_sources": "unsanitized",
    "critical_functions": "critical",
    "endpoints_reach_sink": "ep_reach_sink",
    "endpoints_reach_taint": "ep_reach_taint",
    "shortest_paths_critical": "shortest_critical",
    "all_paths_critical": "all_paths_critical",
    "external_dependencies": "external_deps",
    "vulnerable_deps_reach_critical": "deps_to_critical",
    "attack_paths": "attack_paths",
}

_PATH_QUESTIONS = {"shortest_paths_critical", "all_paths_critical", "attack_paths"}


def _index(payload: dict) -> dict[str, dict]:
    return {n["id"]: n for n in payload.get("nodes", [])}


def _fmt(node: dict | None, nid: str) -> dict[str, Any]:
    if node is None:
        return {"id": nid, "label": nid, "location": nid}
    loc = node.get("file") or ""
    if loc and node.get("line"):
        loc = f"{loc}:{node['line']}"
    return {
        "id": nid,
        "label": node.get("label", nid),
        "location": loc or node.get("label", nid),
        "type": node.get("type"),
        "tags": node.get("tags", []),
        "hotness": (node.get("metrics") or {}).get("hotness"),
        "reachable_sinks": (node.get("metrics") or {}).get("reachable_sinks"),
    }


def _adjacency(payload: dict) -> tuple[dict, dict]:
    out: dict[str, list] = {}
    inn: dict[str, list] = {}
    for e in payload.get("edges", []):
        out.setdefault(e["from"], []).append(e["to"])
        inn.setdefault(e["to"], []).append(e["from"])
    return out, inn


def _reach(start: str, adj: dict, cap: int = 5000) -> set:
    seen = {start}
    q = deque([start])
    while q:
        c = q.popleft()
        for x in adj.get(c, ()):
            if x not in seen:
                seen.add(x)
                q.append(x)
                if len(seen) > cap:
                    return seen
    seen.discard(start)
    return seen


def _blast_radius(payload: dict, target: str | None, limit: int) -> dict[str, Any]:
    idx = _index(payload)
    if not target:
        return {"error": "blast_radius needs a `target` component (a function/file label or path)."}
    t = target.strip().lower()
    matches = [n for n in payload["nodes"]
               if t in (n.get("label", "").lower()) or t in (n.get("file", "").lower())]
    if not matches:
        return {"error": f"No node matches {target!r}."}
    # prefer an exact label match, else the highest-degree match
    chosen = next((n for n in matches if n.get("label", "").lower() == t), None) \
        or max(matches, key=lambda n: n.get("degree", 0))
    out, inn = _adjacency(payload)
    impact = _reach(chosen["id"], inn)   # callers / dependents - hit if it's compromised
    reach = _reach(chosen["id"], out)    # everything it can reach - spread
    return {
        "target": _fmt(chosen, chosen["id"]),
        "ambiguous_matches": [m["label"] for m in matches[:8]] if len(matches) > 1 else [],
        "impact_count": len(impact),
        "reach_count": len(reach),
        "impacted_by_compromise": [_fmt(idx.get(i), i) for i in list(impact)[:limit]],
        "reachable_from_it": [_fmt(idx.get(i), i) for i in list(reach)[:limit]],
    }


def answer(payload: dict, question: str, target: str | None = None, limit: int = 50) -> dict[str, Any]:
    """Answer one security question against the payload. Returns a structured
    dict with ``question``, ``note`` and either ``items`` or ``paths``."""
    if question not in QUESTIONS:
        return {"error": f"Unknown question {question!r}. Available: {', '.join(QUESTIONS)}"}
    label = QUESTIONS[question]
    if question == "blast_radius":
        return {"question": question, "label": label, **_blast_radius(payload, target, limit)}

    layers = payload.get("layers", {})
    L = layers.get(_LAYER[question], {})
    idx = _index(payload)
    note = L.get("note", "")

    if question in _PATH_QUESTIONS:
        paths = L.get("paths", [])[:limit]
        return {
            "question": question, "label": label, "note": note,
            "count": len(L.get("paths", [])),
            "paths": [[_fmt(idx.get(i), i) for i in p] for p in paths],
        }

    # node-list questions: prefer the focused set when present
    ids = L.get("focus") or L.get("nodes", [])
    items = [_fmt(idx.get(i), i) for i in ids[:limit]]
    # critical: order by hotness desc
    if question == "critical_functions":
        items.sort(key=lambda n: -(n.get("hotness") or 0))
    return {"question": question, "label": label, "note": note,
            "count": len(ids), "items": items}
