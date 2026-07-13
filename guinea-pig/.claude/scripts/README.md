# Helper scripts - pick the runtime that works on your OS

Three helpers, each shipped in **three interchangeable forms with the same CLI**,
so you never need a Python interpreter just to run them:

| Tool | What it does |
|---|---|
| `upload_to_mcp` | zip the project and upload it to the Deep Scan MCP `/upload`; prints `upload_id` |
| `fetch_report`  | fetch a scan's report from the API by **job id or upload_id**; `--wait` polls until the job is `done` (recovery path after `session expired`) |
| `canary`        | call the controlled kubeek.com canary endpoints (see [../canary-endpoints.md](../canary-endpoints.md)) |

## Which file to run - try in this order

To avoid depending on a Python install (and the IDE prompting for its path), run
the **native** script first and fall back to Python only if neither runs:

1. **Linux / macOS** - `bash .claude/scripts/<tool>.sh ARGS`
2. **Windows** - `pwsh -NoProfile -File .claude/scripts/<tool>.ps1 ARGS`
   (on Windows PowerShell 5.1: `powershell -NoProfile -File .claude/scripts/<tool>.ps1 ARGS`)
3. **Fallback (any OS)** - `"<python>" .claude/scripts/<tool>.py ARGS`

The three forms take the **same arguments**, e.g.:

```text
upload_to_mcp  [TARGET_DIR] [--base-url URL] [--mcp-config PATH] [--server NAME]
fetch_report   <JOB_ID|UPLOAD_ID> [--format json|md|html|sarif|junit] [--wait] [--interval N] [--timeout N] [--base-url URL]
canary         info [--method GET|POST] | monip | download <f> | direct <f> | download2 <a|b|c>
```

(PowerShell uses `-Flag value`; `.sh`/`.py` use `--flag value`. Same names.)

Requirements: `.sh` needs `curl` (plus `zip` for `upload_to_mcp`, and `jq` for
`fetch_report`'s upload_id resolution / `--wait`); `.ps1` needs PowerShell 5.1+ (no
extra tools); `.py` needs Python 3.9+ (stdlib only).

## Finding Python for the `.py` fallback

Only needed if you reach step 3 and `python3`/`python` isn't on `PATH`. Locate an
interpreter, then run the script with it:

```bash
# Linux / macOS
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && PY="$(ls -1 /usr/bin/python3 /usr/local/bin/python3 "$HOME"/.local/bin/python3 \
                        /opt/homebrew/bin/python3 "$HOME"/.pyenv/shims/python3 2>/dev/null | head -1)"
[ -z "$PY" ] && { echo "no python found" >&2; exit 1; }
"$PY" .claude/scripts/<tool>.py ARGS
```

```powershell
# Windows
$py = (Get-Command python, python3, py -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $py) {
  $py = (Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe" -ErrorAction SilentlyContinue |
         Select-Object -First 1).FullName
}
if (-not $py) { throw "no python found" }
& $py .claude/scripts/<tool>.py ARGS
```
