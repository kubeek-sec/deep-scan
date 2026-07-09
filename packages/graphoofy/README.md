# deepscan-graphoofy

The **AST + algorithmic code-graph** turns a folder of source code
into a queryable graph with tree-sitter.

Used by the `analysis` scanner in `deepscan-core`, which layers a
taint / missing-sanitization security analysis on top of the graph.

## Pipeline

You point it at a **directory** (a repo or a subfolder). Each stage consumes
the previous stage's output; the table below shows what each one *addresses*
and what it *emits*.

```
  ┌─ INPUT ────────────────────────────────────────────────────────────┐
  │  a directory: your repo, or any subfolder you want to scope to      │
  └─────────────────────────────────────────────────────────────────────┘
        │
        ▼
  detect() / collect_files()
  ── walk the tree, classify files by extension, honour
  ── .graphoofyignore / .gitignore, skip sensitive files (secrets, …)
        │   ──▶ list[Path] of code files
        │       (detect() also returns corpus size + warnings)
        ▼
  extract(files)
  ── pass 1: tree-sitter parse each file → classes / functions / imports
  ── pass 2: resolve cross-file imports into typed edges
        │   ──▶ {"nodes": [...], "edges": [...]}
        │       cached under graphoofy-out/cache/
        ▼
  build_from_json(extraction)
  ── assemble a networkx (Di)Graph from the JSON
        │   ──▶ nx.Graph - nodes = symbols/files, edges carry a
        │       `relation` + `confidence` (EXTRACTED / INFERRED / AMBIGUOUS)
        ▼
  cluster(G)
  ── Leiden community detection (stable community ids)
        │   ──▶ {community_id: [node_ids]}
        ▼
  analyze(G, communities)
  ── god_nodes · surprising_connections · suggest_questions
  ── find_import_cycles · graph_diff
        │   ──▶ ranked insight dicts
        ▼
  report.generate(...)   ──▶ Markdown summary
  export.to_json/html/svg/canvas(...)
                         ──▶ graph.json · graph.html · graph.svg · .canvas
```

| Stage | Module | Addresses (input) | Action | Output |
|-------|--------|-------------------|--------|--------|
| Discover | `detect` | a directory | walk + classify + ignore-rules + sensitive-file skip | `list[Path]` (and a corpus-health dict via `detect()`) |
| Extract | `extract` | code files | tree-sitter parse + cross-file import resolution | `{"nodes": [...], "edges": [...]}` (+ on-disk cache) |
| Build | `build` | extraction JSON | hydrate into a graph | `networkx.Graph` / `DiGraph` |
| Cluster | `cluster` | the graph | Leiden communities + cohesion scores | `{community_id: [node_ids]}` |
| Analyze | `analyze` | graph + communities | hubs, surprising links, cycles, suggested questions | insight dicts |
| Report | `report` | all of the above | render a human summary | Markdown string |
| Export | `export` | graph + communities | serialize | `graph.json` / `.html` / `.svg` / `.canvas` |

Edge `confidence` is worth knowing downstream: **EXTRACTED** = read directly
from the AST, **INFERRED** = reconstructed by cross-file import resolution,
**AMBIGUOUS** = a best-effort guess the resolver could not pin down.

## Languages & file types

### Source code via tree-sitter

Only the grammars listed in [`pyproject.toml`](pyproject.toml) ship with the
package. Other languages are still *recognised by extension* but **degrade
gracefully** - `extract()` returns an empty result with an
`error: "tree_sitter_<lang> not installed"` until you `pip install` the grammar.

**Bundled (work out of the box):**

| Language | Extensions |
|----------|------------|
| Python | `.py` |
| JavaScript / TypeScript | `.js .jsx .mjs .ts .tsx` (+ `.vue`) |
| Go | `.go` |
| Rust | `.rs` |
| Java | `.java` |
| C / C++ | `.c .h` · `.cpp .cc .cxx .hpp` |
| Ruby | `.rb` |
| C# | `.cs` |
| PHP | `.php` (+ `*.blade.php`) |
| Bash | `.sh .bash` |

**Recognised but need an optional grammar installed:** Kotlin (`.kt .kts`),
Scala (`.scala`), Swift (`.swift`), Groovy/Gradle (`.groovy .gradle`),
Lua (`.lua .luau .toc`), Zig (`.zig`), Elixir (`.ex .exs`),
Objective-C (`.m .mm`), Julia (`.jl`), Fortran (`.f*/.F*`),
Verilog (`.v .sv .svh`), SQL (`.sql`), PowerShell (`.ps1`),
Terraform/HCL (`.tf .tfvars .hcl`), Pascal/Delphi (`.pas .pp .dpr …`),
DM/BYOND (`.dm .dme .dmi .dmm .dmf`), Dart, Svelte, Astro.

### Structured / non-grammar formats

- **MCP server configs** - `.mcp.json`, `claude_desktop_config.json`,
  `mcp.json`, `mcp_servers.json` (routed by filename). Parsed with the stdlib
  `json` module, so this **always works** with no extra grammar. Emits
  `mcp_server` / `mcp_command` / `mcp_package` / `env_var` nodes (env var
  **names** only - values are never read). See [`mcp_ingest.py`](src/graphoofy/mcp_ingest.py).
- **Config / manifest JSON** - `package.json`, `tsconfig.json`, `*.eslintrc.json`,
  … (needs `tree-sitter-json`). Data-shaped JSON (datasets, GeoJSON, API dumps)
  is deliberately skipped.
- **Markdown** - `.md .mdx .qmd`.
- **.NET project files** - `.sln .slnx`, `.csproj .fsproj .vbproj`,
  `.razor .cshtml`; **Apex** - `.cls .trigger`; **Delphi/Lazarus forms** -
  `.dfm .lfm .lpk`.

### Classified but not graphed

`detect()` also recognises documents (`.txt .rst .html .yaml .yml`), papers
(`.pdf`), images and video/audio, but `extract()` has no extractor for them in
this code-only build, so they never become graph nodes. Office files
(`.docx .xlsx`) are converted to a Markdown sidecar by `detect()` and then
treated as Markdown.

## Public API

```python
from pathlib import Path
import graphoofy

# 1. discover code files under a directory
files = graphoofy.collect_files(Path("src"))

# 2. parse them into nodes + edges (parallel=False keeps it single-process)
extraction = graphoofy.extract(files, cache_root=Path("."), parallel=False)

# 3. build the graph
G = graphoofy.build_from_json(extraction, directed=True)

# 4. communities + insights
communities = graphoofy.cluster(G)
hubs = graphoofy.god_nodes(G)

# 5. serialise
graphoofy.to_json(G, communities, "graphoofy-out/graph.json", force=True)
```

## Running & debugging on a directory

### Through the Deep Scan CLI (the real entry point)

The `analysis` scanner drives this whole pipeline. From the repo root:

```bash
# scan a directory, restricted to the graph/taint analysis scanner
deepscan scan /path/to/code --scanner analysis --debug

# write artifacts (graph.json, graph.html, …) to a chosen folder
deepscan scan /path/to/code --scanner analysis --out ./reports/mygraph
```

`--debug` (or `DEEPSCAN_DEBUG=1`) turns on verbose logging, including the
node/edge counts and per-stage timing emitted by
[`analysis/engine.py`](../core/src/deepscan_core/analysis/engine.py).

### Standalone script (handy for debugging just graphoofy)

Save this anywhere and run it with the workspace interpreter - it runs the full
pipeline in-process so breakpoints work:

```python
# run_graphoofy.py
from pathlib import Path
import graphoofy

target = Path("/path/to/code")
files = graphoofy.collect_files(target)
print(f"{len(files)} files")

# IMPORTANT: parallel=False - the parallel path uses ProcessPoolExecutor,
# whose subprocesses do NOT stop on IDE breakpoints.
extraction = graphoofy.extract(files, cache_root=Path("."), parallel=False)
G = graphoofy.build_from_json(extraction, directed=True)
communities = graphoofy.cluster(G)

print("nodes:", G.number_of_nodes(), "edges:", G.number_of_edges())
print("god nodes:", [h["label"] for h in graphoofy.god_nodes(G)])
graphoofy.to_json(G, communities, "graphoofy-out/graph.json", force=True)
```

```bash
# from packages/graphoofy, with the package importable:
uv run python run_graphoofy.py          # if using uv workspaces
# or:  PYTHONPATH=src python run_graphoofy.py
```

### In PyCharm

1. Open the **monorepo root** as the project and point the interpreter at the
   workspace venv (the one where `deepscan-graphoofy` is installed, e.g. via
   `uv sync` or `pip install -e packages/graphoofy`).
2. **Easiest path** - debug the standalone script above: open `run_graphoofy.py`,
   set breakpoints (e.g. inside `graphoofy.extract` or `build_from_json`), then
   *Run ▸ Debug 'run_graphoofy'*.
3. **Debug the real scanner** - create a *Run/Debug Configuration*:
   - Type: **Module name** = `deepscan_cli.main`
   - Parameters: `scan /path/to/code --scanner analysis --debug`
   - Environment: `DEEPSCAN_DEBUG=1`
   Set a breakpoint in `analysis/engine.py::_analyze` or `_build_graph`.
4. Keep extraction single-process while stepping: the engine already calls
   `extract(..., parallel=False)`, but if you call `extract()` yourself, pass
   `parallel=False` (or set a low `graphoofy_MAX_WORKERS`) so the parser runs in
   the main process and your breakpoints are hit.

> Tip: a run caches per-file extraction under `graphoofy-out/cache/`. Delete that
> folder to force a clean re-parse when a change you made isn't showing up.

## What was dropped from upstream

The LLM (`llm.py`), document/office/Google Workspace converters (Google
Workspace ingestion is removed entirely), URL ingestion, OCR/transcription, the
MCP `serve.py`/`watch.py`/git-hooks/PR tooling, and the various HTML/wiki
visualizers beyond the core `export.py`. The remaining modules
(`detect · extract · build · cluster · analyze · report · export` + their
helpers `cache · mcp_ingest · security · validate · dedup · _minhash`) are the
deterministic, dependency-light graph pipeline.
</content>
</invoke>
