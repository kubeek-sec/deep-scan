"""Precision/expressivity mechanisms layered onto the taint engine, drawn from
Bandit (import-alias resolution, ``# nosec``, computed confidence, safe-forms)
and Pysa (kind-specific sanitizers, parameter-level sinks).

Each test writes a tiny synthetic project so the behaviour is pinned without
depending on the full guinea-pig corpus.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from deepscan_core.analysis import analyze_target, taint


def _kinds(code: str) -> set[str]:
    """Sink kinds the Python taint engine proves for a one-file project."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "a.py"
        p.write_text(code, encoding="utf-8")
        paths = taint.find_taint_paths(taint.build_graph([p], p.parent))
        return {p.kind for p in paths}


def _findings(code: str):
    """Full ``analyze_target`` findings (engine layer: nosec + confidence)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "app.py"
        p.write_text(code, encoding="utf-8")
        return analyze_target(Path(d), Path(d) / "_w", None)


# ----------------------------- import aliases ------------------------------ #

def test_import_alias_resolves_missed_sink():
    # `from os import system as run` previously matched neither os.system nor
    # `system`; the alias map now canonicalises the callee.
    assert _kinds(
        "from os import system as run\n"
        "def h(req):\n    run(req)\n"
    ) == {"command-injection"}


def test_local_def_not_masqueraded_as_sink():
    # A local def sharing a sink's short name must NOT be flagged (no import).
    assert _kinds(
        "def system(x):\n    return x\n"
        "def h(req):\n    system(req)\n"
    ) == set()


# ------------------------------- safe forms -------------------------------- #

def test_yaml_positional_safeloader_is_safe():
    assert _kinds("import yaml\ndef h(t):\n    return yaml.load(t, yaml.SafeLoader)\n") == set()
    assert _kinds("import yaml\ndef h(t):\n    return yaml.load(t)\n") == {"deserialization"}


def test_torch_weights_only_is_safe():
    assert _kinds("import torch\ndef h(p):\n    return torch.load(p, weights_only=True)\n") == set()
    assert _kinds("import torch\ndef h(p):\n    return torch.load(p)\n") == {"deserialization"}


# ------------------------------ catalog gaps ------------------------------- #

def test_new_python_sinks_detected():
    assert _kinds("import dill\ndef h(b):\n    return dill.loads(b)\n") == {"deserialization"}
    assert _kinds("import lxml.etree\ndef h(x):\n    return lxml.etree.fromstring(x)\n") == {"xxe"}
    assert _kinds("import jinja2\ndef h(t):\n    return jinja2.Template(t)\n") == {"template-injection"}
    assert _kinds(
        "from urllib.request import urlopen\ndef h(u):\n    return urlopen(u)\n"
    ) == {"ssrf"}


# --------------------------------- # nosec --------------------------------- #

_CMD = "import os\ndef h(c):\n    os.system(c){tail}\n"


def _kinds_via_engine(code: str):
    res = _findings(code)
    return {f.extra.get("kind") for f in res.findings if f.extra.get("kind")}, res


def test_nosec_blanket_and_scoped():
    base, _ = _kinds_via_engine(_CMD.format(tail=""))
    assert base == {"command-injection"}

    blank, res = _kinds_via_engine(_CMD.format(tail="  # nosec"))
    assert blank == set() and res.graph_summary.get("suppressed_by_nosec") == 1

    scoped_kind, _ = _kinds_via_engine(_CMD.format(tail="  # nosec command-injection"))
    assert scoped_kind == set()

    scoped_cwe, _ = _kinds_via_engine(_CMD.format(tail="  # nosec CWE-78"))
    assert scoped_cwe == set()

    # a nosec scoped to a DIFFERENT kind must not suppress this finding
    wrong, _ = _kinds_via_engine(_CMD.format(tail="  # nosec sql-injection"))
    assert wrong == {"command-injection"}

    # free-text justification (no recognized token) is treated as blanket
    free, _ = _kinds_via_engine(_CMD.format(tail="  # nosec reviewed by appsec"))
    assert free == set()


# ------------------------------- confidence -------------------------------- #

def test_confidence_explicit_vs_parameter_vs_reachable():
    # explicit source read in the sink function -> high
    res = _findings("import os\ndef handle_request(request):\n    os.system(request.args.get('q'))\n")
    f = next(f for f in res.findings if f.extra.get("kind") == "command-injection")
    assert f.extra["confidence"] == "high"
    assert f.extra["features"]["source_evidence"] == "explicit"

    # param-only sink, but reachable from a web entry point -> bumped to high
    res = _findings(
        "import os\n"
        "def run_cmd(cmd):\n    os.system(cmd)\n"
        "def handle_request(request):\n    run_cmd(request.args.get('v'))\n"
    )
    f = next(f for f in res.findings if f.extra.get("kind") == "command-injection")
    assert f.extra["confidence"] == "high"
    assert f.extra["features"]["source_evidence"] == "parameter"

    # internal-only param sink (no web/cli exposure) -> stays medium
    res = _findings("import os\ndef _helper(cmd):\n    os.system(cmd)\n")
    f = next(f for f in res.findings if f.extra.get("kind") == "command-injection")
    assert f.extra["confidence"] == "medium"


# ------------------------ kind-specific sanitizers ------------------------- #

def test_sanitizer_is_kind_specific():
    # html.escape clears xss, NOT sql-injection
    assert _kinds(
        "import html\ndef h(req, cur):\n    y = html.escape(req)\n    cur.execute('SELECT ' + y)\n"
    ) == {"sql-injection"}
    # ...and DOES clear an xss sink
    assert _kinds(
        "import html\n"
        "from django.utils.safestring import mark_safe\n"
        "def h(req):\n    y = html.escape(req)\n    return mark_safe(y)\n"
    ) == set()
    # shlex.quote clears command-injection, not path-traversal
    assert _kinds("import shlex\ndef h(req):\n    open(shlex.quote(req))\n") == {"path-traversal"}


def test_sanitization_carries_through_copy():
    # a sanitized value copied to another name stays sanitized (no false positive)
    assert _kinds(
        "import shlex, os\n"
        "def h(req):\n    safe = shlex.quote(req)\n    safe2 = safe\n    os.system(safe2)\n"
    ) == set()


# ------------------------- parameter-level sinks --------------------------- #

def test_parameter_level_sink_gating():
    # SSRF is the URL arg, not the body/params
    assert _kinds("import requests\ndef h(req):\n    requests.get(req)\n") == {"ssrf"}
    assert _kinds(
        "import requests\ndef h(req):\n    requests.get('https://api/x', params=req)\n"
    ) == set()
    # SQL is the query text, not the bound parameters
    assert _kinds("def h(req, cur):\n    cur.execute('SELECT * FROM t WHERE x=?', (req,))\n") == set()
    assert _kinds("def h(req, cur):\n    cur.execute('SELECT ' + req)\n") == {"sql-injection"}
    # open() danger is the path, not the mode
    assert _kinds("def h(req):\n    open('/etc/fixed', req)\n") == set()
    assert _kinds("def h(req):\n    open(req)\n") == {"path-traversal"}
