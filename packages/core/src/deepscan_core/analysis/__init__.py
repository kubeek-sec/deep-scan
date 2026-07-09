"""Code-graph security analysis for the ``analysis`` scanner.

Precise, deterministic taint analysis (no AI), uniform across every supported
language. Two collectors feed one shared propagation core (``taint_core``):

* ``taint`` - Python AST collector (source → sink across function boundaries,
  sanitizer-aware).
* ``ts_taint`` - generic tree-sitter collector for the other installed grammar
  families (js/ts, java, go, ruby, php, c#, rust, c/cpp).

Both prove a data-flow from an untrusted source to a dangerous sink, so all
findings are high confidence. (``treesitter_scan`` remains as a standalone
coarse call-site scanner / knowledge-base test utility, but is no longer part
of the analysis pipeline.)

``engine.analyze_target`` ties them together, builds the graphoofy code graph
(the knowledge base + reachability), and returns normalized ``Finding`` objects
plus the graph artifacts.
"""

from .engine import AnalysisResult, analyze_target, security_payload
from .query import QUESTIONS, answer
from .taint_core import AnalysisAborted

__all__ = [
    "AnalysisResult", "analyze_target", "security_payload",
    "QUESTIONS", "answer", "AnalysisAborted",
]
