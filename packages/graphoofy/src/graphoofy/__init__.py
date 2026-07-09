"""graphoofy - extract · build · cluster · analyze · report.

This is the **AST + algorithmic code-graph**. The document/image/video ingestion and all
LLM/semantic features are intentionally omitted; this package turns a folder of
source code into a queryable graph using tree-sitter, with no network access
and no AI.

Pipeline: ``detect() → extract() → build() → cluster() → analyze() → report()``.
``export`` writes the graph as JSON/HTML/SVG/canvas.
"""


def __getattr__(name):
    # Lazy imports so importing the package is cheap and a missing optional
    # dependency only bites when that stage is actually used.
    _map = {
        "extract": ("graphoofy.extract", "extract"),
        "collect_files": ("graphoofy.extract", "collect_files"),
        "build": ("graphoofy.build", "build"),
        "build_from_json": ("graphoofy.build", "build_from_json"),
        "cluster": ("graphoofy.cluster", "cluster"),
        "score_all": ("graphoofy.cluster", "score_all"),
        "cohesion_score": ("graphoofy.cluster", "cohesion_score"),
        "god_nodes": ("graphoofy.analyze", "god_nodes"),
        "surprising_connections": ("graphoofy.analyze", "surprising_connections"),
        "suggest_questions": ("graphoofy.analyze", "suggest_questions"),
        "generate": ("graphoofy.report", "generate"),
        "to_json": ("graphoofy.export", "to_json"),
        "to_html": ("graphoofy.export", "to_html"),
        "to_svg": ("graphoofy.export", "to_svg"),
        "to_canvas": ("graphoofy.export", "to_canvas"),
    }
    if name in _map:
        import importlib

        mod_name, attr = _map[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr)
    raise AttributeError(f"module 'graphoofy' has no attribute {name!r}")
