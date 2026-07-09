# Wiring the MCP server into your own project

The [MCP server](interfaces.md#mcp-server) exposes the Deep Scan scanners to
agents and IDE assistants as tools (`static_scan`, `scan_family`, `query_graph`,
…). To drive it from an agent working inside *your* repository you drop two
things from `guinea-pig/` into that repository:

| What you copy | Why |
|---|---|
| **`.mcp.json`** | Tells the MCP client (Claude Code, an IDE assistant, …) **where** the Deep Scan server is. This is the one file you edit when the server isn't on your machine. |
| **`.claude/`** | The workflow that drives the server: the `/security*` slash commands, the `upload_to_mcp` / `fetch_report` helper scripts (`.sh`/`.ps1`/`.py`), and `settings.local.json` which enables the `deepscan` server. |

The rest of `guinea-pig/` (the vulnerable fixtures) is **not** needed — only
`.mcp.json` and `.claude/`.

---

## 1. Copy the two into your project

From your project's root, pointing at your `deep-scan` checkout:

```bash
DEEP_SCAN=/path/to/deep-scan          # adjust to your checkout

cp    "$DEEP_SCAN/guinea-pig/.mcp.json" .
cp -R "$DEEP_SCAN/guinea-pig/.claude"   .
```

The result is:

```text
your-project/
├── .mcp.json                 # ← MCP client config (edit for a remote server, §2)
└── .claude/
    ├── settings.local.json   # enables the "deepscan" server
    ├── canary-endpoints.md   # the only external addresses the /security* flow may hit
    ├── commands/             # /security, /security-eval, /security-patch
    └── scripts/              # upload_to_mcp, fetch_report, canary (.sh/.ps1/.py)
```

> **Already have a `.claude/`?** Don't clobber it — merge instead: copy the
> `commands/` and `scripts/` files in, and add `"deepscan"` to
> `enabledMcpjsonServers` in your existing `settings.local.json`.

---

## 2. Point `.mcp.json` at the server

The shipped `.mcp.json` assumes the server runs **on your machine** (loopback):

```json
{
  "mcpServers": {
    "deepscan": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

If that's true — you ran `./start.sh` locally — you're done; skip to §3.

### When the server is not local

Edit the `url` and replace `127.0.0.1` with the **IP address or hostname** of
the machine running the Deep Scan server:

```json
{
  "mcpServers": {
    "deepscan": {
      "type": "http",
      "url": "http://192.168.1.50:8000/mcp"
    }
  }
}
```

Keep the rest of the URL intact:

| Part | Change it? |
|---|---|
| `192.168.1.50` (host) | **Yes** — the server's reachable IP or DNS name (e.g. `scanner.internal`). |
| `:8000` (port) | Only if the server publishes a different port (e.g. a mapped Docker/host port). |
| `/mcp` (path) | **Never remove it, and never add a trailing slash.** The endpoint is served at exactly `/mcp`; a trailing `/mcp/` triggers a 307 redirect that MCP clients (Claude included) don't follow cleanly, and the connection fails. |
| `http` → `https` | Only if the server sits behind TLS termination. |

Two things must also be true **server-side** for a remote connection to work:

- The server must bind `0.0.0.0`, not loopback — set `FASTMCP_HOST=0.0.0.0`
  (the Docker image already does this) so the port is reachable from other
  hosts, and make sure that port is open.
- To scan over http the project is **uploaded** first (the server is remote and
  can't read your local disk); the helper in §4 handles this. A server-side
  `project_dir` path is refused over http unless the server sets
  `DEEPSCAN_MCP_ALLOW_LOCAL_PATHS=1`.

### Don't forget the API URL for `fetch_report`

`upload_to_mcp` reads the server address straight from `.mcp.json`, so once you
edit the `url` above, uploads go to the right place automatically. But
`fetch_report` talks to the **REST API** (default `http://127.0.0.1:8800`), a
*separate* port from the MCP server. When the stack is remote, point it there
too — either per call or via an env var:

```bash
export DEEPSCAN_API_URL=http://192.168.1.50:8800
# or per call:
bash .claude/scripts/fetch_report.sh <JOB_ID> --base-url http://192.168.1.50:8800
```

---

## 3. Enable the server in your MCP client

The copied `.claude/settings.local.json` already opts the project into the
server:

```json
{ "enabledMcpjsonServers": ["deepscan"] }
```

Reload the project so the client picks up `.mcp.json` (Claude Code may also
prompt you to approve the project-scoped server the first time). The `deepscan`
tools are **deferred** — load them before first use:

```text
ToolSearch select:mcp__deepscan__static_scan,mcp__deepscan__scan_family,mcp__deepscan__query_graph,mcp__deepscan__list_graph_questions
```

Sanity-check the connection with `tool_status` or `list_scanners` — either
returning cleanly means the client reached the server at the `url` you set.

---

## 4. Use it

The easy path is the shipped slash commands:

- **`/security-eval`** — zip + upload your project, scan it through the jobs
  infrastructure, fetch the report, and produce a prioritized remediation plan.
- **`/security-patch`** — turn that plan into one review branch per fix.
- **`/security`** — both, end to end.

Under the hood that's three steps you can also run by hand — the helpers ship as
`.sh` (Linux/macOS) → `.ps1` (Windows) → `.py` (fallback), same arguments (see
[`.claude/scripts/README.md`](../guinea-pig/.claude/scripts/README.md)):

```bash
# 1. zip + upload the project — reads the server URL from .mcp.json, prints an upload_id
UPLOAD_ID=$(bash .claude/scripts/upload_to_mcp.sh .)

# 2. scan via the jobs infrastructure (MCP tool call) — note the "Job #N" it returns
#    static_scan(upload_id=$UPLOAD_ID)   or   scan_family("sast", upload_id=$UPLOAD_ID)

# 3. fetch the finished report by job id (API — see the URL note in §2)
bash .claude/scripts/fetch_report.sh <N> --format md > reports/security-report.md
```

`upload_to_mcp` accepts `--base-url`, `--mcp-config` and `--server` if you'd
rather override the address than edit `.mcp.json`.

> **A note on the `/security*` commands.** They enforce an **external-address
> policy**: the only host any demonstration or regression test may contact is a
> controlled `kubeek.com` canary endpoint (see
> [`.claude/canary-endpoints.md`](../guinea-pig/.claude/canary-endpoints.md)).
> That contract exists for the guinea-pig fixtures; keep it if you want the same
> guardrail on your own repo, or trim the canary pieces if you don't need them.

---

**See also:** [MCP server tools & transports](interfaces.md#mcp-server) ·
[deployment & remote stacks](deployment.md) · [scanner catalog](scanners.md)
