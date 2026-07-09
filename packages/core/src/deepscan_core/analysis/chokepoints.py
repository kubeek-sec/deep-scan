"""Choke-point analysis: the best single places to fix.

Over the function call graph, computes:

* **Dominators** - for the function containing each finding (the "sink
  function"), the functions that *every* path from an entry point to it must
  pass through. A validation placed on a dominator neutralises the finding no
  matter which path the attacker takes. (A virtual super-source linked to every
  entry point lets one dominator tree cover all entries at once.)
* **Betweenness centrality** - functions that lie on many call paths; used to
  rank and to surface central code even when it dominates nothing.

A *choke point* is a function that dominates one or more findings' sink
functions. Ranking by how many distinct findings it covers answers: "fix here
to mitigate N issues at once."

Pure graph algorithms (NetworkX); nothing is executed.
"""

from __future__ import annotations

from typing import Any

_SUPER_SOURCE = "__deepscan_super_source__"
_MAX_BETWEENNESS_NODES = 3000  # skip the O(V·E) centrality on very large graphs
_MAX_DOMINATORS_PER_FINDING = 5
_TOP_CHOKE_POINTS = 15


def analyze(cg, findings: list) -> dict[str, Any]:
    """Return ``{"choke_points": [...], "per_finding": {idx: [...]}}`` and, as a
    side effect, write ``extra["choke_points"]`` onto each finding it can map.

    *cg* is a ``reachability.CallGraph``; *findings* the analysis findings.
    """
    import networkx as nx

    result: dict[str, Any] = {"choke_points": [], "per_finding": {}}
    G = cg.call_digraph()
    if G.number_of_nodes() == 0:
        return result

    entries = [e for e in cg.entry_point_ids() if e in G]
    if not entries:
        return result

    # One dominator tree from a virtual super-source over all entry points.
    H = G.copy()
    H.add_node(_SUPER_SOURCE)
    for e in entries:
        H.add_edge(_SUPER_SOURCE, e)
    try:
        idom = nx.immediate_dominators(H, _SUPER_SOURCE)
    except Exception:  # noqa: BLE001
        return result

    betweenness: dict[str, float] = {}
    if G.number_of_nodes() <= _MAX_BETWEENNESS_NODES:
        try:
            betweenness = nx.betweenness_centrality(G)
        except Exception:  # noqa: BLE001
            betweenness = {}

    def dominators(node: str) -> list[str]:
        """Strict dominators of *node*, nearest-first, excluding the node and the
        super-source."""
        out: list[str] = []
        cur = idom.get(node)
        seen = {node}
        while cur is not None and cur not in seen and cur != _SUPER_SOURCE:
            out.append(cur)
            seen.add(cur)
            cur = idom.get(cur)
        return out

    coverage: dict[str, set[int]] = {}
    for idx, f in enumerate(findings):
        file, _, line = f.location.partition(":")
        try:
            line_no = int(line)
        except ValueError:
            continue
        sink_fn = cg.enclosing_id(file, line_no)
        if sink_fn is None or sink_fn not in idom:
            continue
        doms = dominators(sink_fn)
        chokes = []
        for d in doms[:_MAX_DOMINATORS_PER_FINDING]:
            meta = cg.func_meta(d)
            if meta:
                chokes.append({"label": meta["label"], "location": meta["location"]})
            coverage.setdefault(d, set()).add(idx)
        if chokes:
            f.extra["choke_points"] = chokes
            result["per_finding"][idx] = chokes

    ranked = sorted(
        coverage.items(),
        key=lambda kv: (-len(kv[1]), -betweenness.get(kv[0], 0.0)),
    )
    entry_set = set(entries)
    for node, covered in ranked[:_TOP_CHOKE_POINTS]:
        meta = cg.func_meta(node)
        if not meta:
            continue
        covered_locs = sorted(
            {findings[i].location for i in covered if i < len(findings)}
        )
        result["choke_points"].append({
            "label": meta["label"],
            "location": meta["location"],
            "covers": len(covered),
            "covered_locations": covered_locs,
            "betweenness": round(betweenness.get(node, 0.0), 4),
            "is_entry_point": node in entry_set,
        })
    return result
