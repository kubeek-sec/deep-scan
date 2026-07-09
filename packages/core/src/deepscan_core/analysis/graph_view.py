"""Build the security-annotated graph payload that powers ``graph.html``.

Turns the graphoofy code graph + the analysis findings + the call-graph
reachability into a single JSON the viewer renders, following the model in
``docs/graph``: nodes carry a **type** and security **tags** (SOURCE, SINK,
SANITIZER, ENTRY, CRITICAL, EXTERNAL, TAINT) and **metrics** (degree, fan-in/out,
pagerank, reachable_sinks, hotness); precomputed **layers** answer the security
questions (unsanitized sources, critical functions, endpoints→sink/taint,
shortest/all paths to critical functions, external dependencies, vulnerable-
reaching-critical, attack paths). Blast radius is computed interactively in the
viewer.

Everything is derived from the static graph; nothing is executed. Depth is
bounded by the extraction: precise taint covers every supported language now,
but there is no CFG/DFG/trust-boundary modelling yet.
"""

from __future__ import annotations

import math
import re

from . import sinks


def _is_taint(extra: dict | None) -> bool:
    """True for a proven-taint finding from either collector.

    Both engines label findings ``analysis/taint-<family>`` (``-python``, ``-go``
    …), so a prefix test recognizes them all uniformly.
    """
    return str((extra or {}).get("engine") or "").startswith("analysis/taint")


_EXT_RE = re.compile(r"\.[A-Za-z0-9]+$")
_N_CRITICAL = 25
_BETWEENNESS_MAX = 2500       # skip O(V·E) centrality above this
_ALL_PATHS_MAX_FUNCS = 1500   # skip the explosive all-simple-paths above this
_ALL_PATHS_CUTOFF = 8
_ALL_PATHS_CAP = 150
_ATTACK_PATHS_CAP = 60

_ALL_SANITIZERS = set().union(*sinks.SANITIZERS.values())


def _node_type(label: str, has_src: bool) -> str:
    if label.endswith("()"):
        return "function"
    if _EXT_RE.search(label or ""):
        return "file"
    if not has_src:
        return "library"
    short = label.split(".")[-1]
    return "class" if short[:1].isupper() else "symbol"


def _positions(G, node_to_comm: dict) -> dict:
    """Deterministic node positions, computed once at scan time so the viewer
    loads instantly (no browser physics) and positions stay stable across
    interactions. Spring layout for small graphs; a fast community-circle
    packing for large ones."""
    import networkx as nx
    from collections import defaultdict

    n = G.number_of_nodes()
    if n == 0:
        return {}
    if n <= 2000:
        try:
            pos = nx.spring_layout(G, seed=42, k=1.0 / math.sqrt(max(1, n)), iterations=40)
            return {k: (float(v[0]) * 1500, float(v[1]) * 1500) for k, v in pos.items()}
        except Exception:  # noqa: BLE001
            pass

    # Large graph: lay out the *community meta-graph* with a force layout (a few
    # hundred nodes - fast), then cluster each community's members around its
    # centre. Organic (communities spread by their connectivity), not concentric
    # rings, and O(N).
    members_by: dict = defaultdict(list)
    for nid in G.nodes:
        members_by[node_to_comm.get(nid, -1)].append(nid)
    meta = nx.Graph()
    meta.add_nodes_from(members_by)
    for u, v in G.edges():
        cu, cv = node_to_comm.get(u, -1), node_to_comm.get(v, -1)
        if cu != cv:
            meta.add_edge(cu, cv)
    try:
        cpos = nx.spring_layout(
            meta, seed=42, k=1.2 / math.sqrt(max(1, meta.number_of_nodes())), iterations=60)
    except Exception:  # noqa: BLE001
        cpos = {c: (math.cos(2 * math.pi * i / max(1, len(members_by))),
                    math.sin(2 * math.pi * i / max(1, len(members_by))))
                for i, c in enumerate(members_by)}
    scale = 220 * math.sqrt(max(1, len(members_by)))
    pos: dict = {}
    for cid, members in members_by.items():
        cx, cy = cpos.get(cid, (0.0, 0.0))
        cx, cy = cx * scale, cy * scale
        m = len(members)
        base = 40 + 16 * math.sqrt(m)
        for i, nid in enumerate(members):
            a = 2.399963 * i  # golden-angle spiral → even, non-ringed packing
            r = base * math.sqrt((i + 0.5) / m)
            pos[nid] = (cx + r * math.cos(a), cy + r * math.sin(a))
    return pos


def _short_path_from_entry(Gf, target, entry_set, reverse_adj):
    """Shortest path entry → target via reverse BFS from target until an entry
    point is hit. Returns the forward path (entry → … → target) or None."""
    if target in entry_set:
        return [target]
    from collections import deque

    q = deque([target])
    prev = {target: None}
    while q:
        cur = q.popleft()
        for p in reverse_adj.get(cur, ()):
            if p not in prev:
                prev[p] = cur
                if p in entry_set:
                    path = [p]
                    k = p
                    while prev[k] is not None:
                        k = prev[k]
                        path.append(k)
                    return path  # p → … → target (already forward)
                q.append(p)
    return None


def build(G, findings: list, cg, communities: dict | None) -> dict:
    import networkx as nx

    communities = communities or {}
    node_to_comm: dict = {}
    for cid, members in communities.items():
        for nid in members:
            node_to_comm[nid] = cid

    # ---- function call graph + reachability helpers ----
    Gf = cg.call_digraph() if cg is not None else nx.DiGraph()
    rev_adj: dict = {}
    for u, v in Gf.edges():
        rev_adj.setdefault(v, []).append(u)

    entry_ids = set(cg.entry_point_ids()) if cg is not None else set()
    # Endpoints = externally-invoked entries (web/cli); fall back to all entries.
    endpoints = set()
    for nid in entry_ids:
        info = cg._reach.get(nid) if cg is not None else None
        if info and info.entry_kind in ("web", "cli"):
            endpoints.add(nid)
    if not endpoints:
        endpoints = set(entry_ids)

    # ---- map findings to their enclosing function node ----
    sink_funcs: set = set()
    taint_funcs: set = set()
    sink_severity: dict = {}
    for f in findings:
        file, _, line = f.location.partition(":")
        try:
            ln = int(line)
        except ValueError:
            continue
        fn = cg.enclosing_id(file, ln) if cg is not None else None
        if not fn:
            continue
        sink_funcs.add(fn)
        sink_severity[fn] = min(sink_severity.get(fn, 99), f.severity.rank)
        if _is_taint(f.extra):
            taint_funcs.add(fn)

    unsan_sink_funcs: set = set()
    for f in findings:
        e = f.extra or {}
        if _is_taint(e) or e.get("unsanitized"):
            file, _, line = f.location.partition(":")
            try:
                fn = cg.enclosing_id(file, int(line)) if cg is not None else None
            except ValueError:
                fn = None
            if fn:
                unsan_sink_funcs.add(fn)

    # ---- sanitizers (by name) ----
    sanitizer_funcs = set()
    for nid in Gf.nodes:
        name = (cg.func_meta(nid) or {}).get("label", "")[:-2]
        short = name.rsplit(".", 1)[-1]
        if short in _ALL_SANITIZERS or name in _ALL_SANITIZERS:
            sanitizer_funcs.add(nid)

    # ---- reachable_sinks per function (reverse BFS from each sink) ----
    reachable_sinks: dict = {}
    can_reach_sink: set = set()
    can_reach_taint: set = set()
    for s in sink_funcs:
        anc = nx.ancestors(Gf, s) if s in Gf else set()
        for a in anc:
            reachable_sinks[a] = reachable_sinks.get(a, 0) + 1
            can_reach_sink.add(a)
        can_reach_sink.add(s)
        if s in taint_funcs:
            can_reach_taint.update(anc)
            can_reach_taint.add(s)

    # ---- centrality ----
    try:
        pagerank = nx.pagerank(Gf) if Gf.number_of_nodes() else {}
    except Exception:  # noqa: BLE001
        pagerank = {}
    betweenness: dict = {}
    if 0 < Gf.number_of_nodes() <= _BETWEENNESS_MAX:
        try:
            betweenness = nx.betweenness_centrality(Gf)
        except Exception:  # noqa: BLE001
            betweenness = {}

    # ---- hotness → critical ----
    hotness: dict = {}
    for nid in Gf.nodes:
        fan_in = Gf.in_degree(nid)
        score = fan_in * 3 + reachable_sinks.get(nid, 0) * 5 + pagerank.get(nid, 0) * 1000 \
            + betweenness.get(nid, 0) * 50
        if score > 0:
            hotness[nid] = round(score, 2)
    critical = {nid for nid, _ in sorted(hotness.items(), key=lambda kv: -kv[1])[:_N_CRITICAL]}
    can_reach_critical: set = set()
    for c in critical:
        if c in Gf:
            can_reach_critical.update(nx.ancestors(Gf, c))

    # ---- external dependencies (library nodes) + importers ----
    lib_importers: dict = {}
    for u, v, d in G.edges(data=True):
        if d.get("relation") == "imports":
            lib_importers.setdefault(v, set()).add(u)
    external_ids = [nid for nid in G.nodes if _node_type(
        str(G.nodes[nid].get("label") or nid), bool(G.nodes[nid].get("source_file"))) == "library"]

    # ---- nodes payload ----
    nodes = []
    pos = _positions(G, node_to_comm)
    for nid in G.nodes:
        attrs = G.nodes[nid]
        label = str(attrs.get("label") or nid)
        ntype = _node_type(label, bool(attrs.get("source_file")))
        tags = []
        if nid in endpoints:
            tags.append("ENTRY")
        if nid in sink_funcs:
            tags.append("SINK")
        if nid in taint_funcs:
            tags.append("TAINT")
        if nid in sanitizer_funcs:
            tags.append("SANITIZER")
        if nid in critical:
            tags.append("CRITICAL")
        if ntype == "library":
            tags.append("EXTERNAL")
        x, y = pos.get(nid, (0.0, 0.0))
        nodes.append({
            "id": nid, "label": label, "type": ntype,
            "file": attrs.get("source_file") or "", "line": str(attrs.get("source_location") or ""),
            "community": node_to_comm.get(nid, -1),
            "degree": G.degree(nid), "fan_in": G.in_degree(nid), "fan_out": G.out_degree(nid),
            "tags": tags,
            "metrics": {"reachable_sinks": reachable_sinks.get(nid, 0),
                        "pagerank": round(pagerank.get(nid, 0.0), 5),
                        "betweenness": round(betweenness.get(nid, 0.0), 4),
                        "hotness": hotness.get(nid, 0)},
            "x": round(x, 1), "y": round(y, 1),
        })

    edges = [{"from": u, "to": v, "rel": (d.get("relation") or "").upper()}
             for u, v, d in G.edges(data=True)]

    # ---- layers ----
    def epaths_to(targets):
        out = []
        for t in targets:
            p = _short_path_from_entry(Gf, t, endpoints, rev_adj)
            if p and len(p) >= 1:
                out.append(p)
        return out

    ep_reach_sink = sorted(endpoints & can_reach_sink)
    ep_reach_taint = sorted(endpoints & can_reach_taint)

    # shortest paths endpoint → each critical function
    shortest_critical = [p for p in epaths_to(sorted(critical)) if p and len(p) >= 2]

    # all simple paths endpoint → critical (bounded)
    all_paths_critical = []
    if 0 < Gf.number_of_nodes() <= _ALL_PATHS_MAX_FUNCS:
        for c in sorted(critical):
            for ep in sorted(endpoints):
                if ep == c or c not in Gf or ep not in Gf:
                    continue
                try:
                    for p in nx.all_simple_paths(Gf, ep, c, cutoff=_ALL_PATHS_CUTOFF):
                        all_paths_critical.append(p)
                        if len(all_paths_critical) >= _ALL_PATHS_CAP:
                            break
                except Exception:  # noqa: BLE001
                    pass
                if len(all_paths_critical) >= _ALL_PATHS_CAP:
                    break
            if len(all_paths_critical) >= _ALL_PATHS_CAP:
                break

    # attack paths: endpoint → sink, ranked by sink severity (lower rank = worse)
    attack = []
    for s in sorted(sink_funcs, key=lambda s: sink_severity.get(s, 99)):
        p = _short_path_from_entry(Gf, s, endpoints, rev_adj)
        if p and len(p) >= 2:
            attack.append({"path": p, "severity_rank": sink_severity.get(s, 99)})
        if len(attack) >= _ATTACK_PATHS_CAP:
            break

    # vulnerable external deps reaching a critical function (structural; CVE
    # overlay needs SCA - see reachable-deps scanner).
    deps_to_critical = []
    for lib in external_ids:
        importers = lib_importers.get(lib, set())
        if any(imp in can_reach_critical or imp in critical for imp in importers):
            deps_to_critical.append(lib)

    layers = {
        "unsanitized": {"nodes": sorted(unsan_sink_funcs),
                        "paths": epaths_to(sorted(unsan_sink_funcs)),
                        "note": "Sinks reached by untrusted input with no sanitizer on the path (red); the entry points feeding them are the unsanitized sources."},
        "critical": {"nodes": sorted(critical),
                     "note": "Most critical functions by hotness = fan-in·3 + reachable_sinks·5 + pagerank + betweenness."},
        "ep_reach_sink": {"nodes": sorted(set(ep_reach_sink) | sink_funcs),
                          "focus": ep_reach_sink, "paths": epaths_to(sorted(sink_funcs)),
                          "note": "Endpoints (web/CLI) from which a dangerous sink is reachable."},
        "ep_reach_taint": {"nodes": sorted(set(ep_reach_taint) | taint_funcs),
                           "focus": ep_reach_taint, "paths": epaths_to(sorted(taint_funcs)),
                           "note": "Endpoints from which a proven-tainted sink (data-flow confirmed) is reachable."},
        "shortest_critical": {"paths": shortest_critical, "nodes": sorted(critical),
                              "note": "Shortest path from an endpoint to each critical function."},
        "all_paths_critical": {"paths": all_paths_critical, "nodes": sorted(critical),
                               "note": f"All paths (≤{_ALL_PATHS_CUTOFF} hops, capped {_ALL_PATHS_CAP}) from endpoints to critical functions." + ("" if all_paths_critical or Gf.number_of_nodes() <= _ALL_PATHS_MAX_FUNCS else " Skipped: graph too large - use shortest paths.")},
        "external_deps": {"nodes": sorted(external_ids),
                          "note": "External libraries imported by the application."},
        "deps_to_critical": {"nodes": sorted(set(deps_to_critical) | critical),
                             "focus": sorted(deps_to_critical),
                             "note": "External dependencies whose importing code reaches a critical function - the ones whose CVEs would matter most (cross with the reachable-deps scanner for actual CVEs)."},
        "attack_paths": {"paths": [a["path"] for a in attack], "nodes": sorted(sink_funcs),
                         "note": "Entry → sink attack paths, ranked by sink severity (highest impact first)."},
        "blast_radius": {"nodes": [], "note": "Click any node: its callers (impact) and everything it reaches (spread) light up - the blast radius if it were compromised."},
    }

    return {
        "nodes": nodes, "edges": edges, "layers": layers,
        "communityCount": len(communities),
        "counts": {"functions": Gf.number_of_nodes(), "endpoints": len(endpoints),
                   "sinks": len(sink_funcs), "critical": len(critical),
                   "external": len(external_ids)},
    }
