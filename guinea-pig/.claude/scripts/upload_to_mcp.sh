#!/usr/bin/env bash
# Zip the project and upload it to the Deep Scan MCP server's /upload endpoint
# (mirror of upload_to_mcp.py - same CLI). Prints the returned upload_id to
# stdout; pass it to a scan tool, e.g. static_scan(upload_id=<id>).
#
#   upload_to_mcp.sh [TARGET_DIR]
#   upload_to_mcp.sh src/python --base-url http://127.0.0.1:8000
#
# Needs: curl, zip (jq optional - used for robust JSON parsing when present).
# The MCP base URL comes from .mcp.json (the deepscan server's url, with a
# trailing /mcp stripped) unless --base-url is given.
set -euo pipefail

TARGET="."
MCP_CONFIG=".mcp.json"
SERVER="deepscan"
BASE_URL=""
SKIP_DIRS=(.hg .svn .venv venv node_modules __pycache__ .tox .nox dist build \
           .mypy_cache .pytest_cache .ruff_cache .idea target)
# Exact project-relative files to leave OUT of the zip: the guinea-pig's own
# test-harness scaffolding (canary endpoints, /security-* commands, helper
# scripts) - tooling, not code under test. EXACT paths, NOT the whole .claude,
# so real skills/commands a target project keeps under .claude are still scanned.
SKIP_FILES=(
  .claude/canary-endpoints.md
  .claude/settings.local.json
  .claude/commands/security.md
  .claude/commands/security-eval.md
  .claude/commands/security-patch.md
  .claude/scripts/README.md
  .claude/scripts/canary.py
  .claude/scripts/canary.sh
  .claude/scripts/canary.ps1
  .claude/scripts/fetch_report.py
  .claude/scripts/fetch_report.sh
  .claude/scripts/fetch_report.ps1
  .claude/scripts/upload_to_mcp.py
  .claude/scripts/upload_to_mcp.sh
  .claude/scripts/upload_to_mcp.ps1
)
MAX_BYTES=$((200 * 1024 * 1024))

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//' >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --mcp-config) MCP_CONFIG="$2"; shift 2 ;;
    --mcp-config=*) MCP_CONFIG="${1#*=}"; shift ;;
    --server) SERVER="$2"; shift 2 ;;
    --server=*) SERVER="${1#*=}"; shift ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --base-url=*) BASE_URL="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "error: unknown option: $1" >&2; exit 2 ;;
    *) TARGET="$1"; shift ;;
  esac
done

command -v zip >/dev/null 2>&1 || { echo "error: 'zip' not found - install zip or use the .py fallback" >&2; exit 3; }
[ -d "$TARGET" ] || { echo "error: not a directory: $TARGET" >&2; exit 2; }

# Resolve the MCP base URL.
if [ -z "$BASE_URL" ]; then
  [ -f "$MCP_CONFIG" ] || { echo "error: $MCP_CONFIG not found (pass --base-url)" >&2; exit 2; }
  if command -v jq >/dev/null 2>&1; then
    url="$(jq -r --arg s "$SERVER" '.mcpServers[$s].url // (.mcpServers | to_entries[0].value.url) // empty' "$MCP_CONFIG")"
  else
    url="$(grep -oE '"url"[[:space:]]*:[[:space:]]*"[^"]*"' "$MCP_CONFIG" | head -1 | sed -E 's/.*"([^"]*)"$/\1/' || true)"
  fi
  [ -n "$url" ] || { echo "error: no MCP server url in $MCP_CONFIG (stdio transport? pass --base-url)" >&2; exit 2; }
  BASE_URL="$url"
fi
BASE_URL="${BASE_URL%/}"
case "$BASE_URL" in */mcp) BASE_URL="${BASE_URL%/mcp}" ;; esac
UPLOAD_URL="$BASE_URL/upload"

# Build the zip, excluding VCS/dependency/build dirs (top-level and nested).
excludes=()
for d in "${SKIP_DIRS[@]}"; do excludes+=(-x "$d/*" "*/$d/*"); done
# Exact-path file excludes (see SKIP_FILES): drop only these known harness files.
for f in "${SKIP_FILES[@]}"; do excludes+=(-x "$f"); done

tmpzip="$(mktemp -t upload_XXXXXX.zip)"
trap 'rm -f "$tmpzip"' EXIT
name="$(basename "$(cd "$TARGET" && pwd)")"

echo "zipping $TARGET …" >&2
( cd "$TARGET" && rm -f "$tmpzip" && zip -r -q -X "$tmpzip" . "${excludes[@]}" )

zbytes="$(wc -c < "$tmpzip")"
if [ "$zbytes" -gt "$MAX_BYTES" ]; then
  echo "error: zip is $((zbytes / 1024 / 1024)) MiB > 200 MiB limit - remove build/vendor dirs" >&2
  exit 1
fi
echo "uploading $((zbytes / 1024 / 1024)) MiB to $UPLOAD_URL …" >&2

# URL-encode the filename when jq is available; otherwise pass it as-is.
if command -v jq >/dev/null 2>&1; then
  fname="$(jq -rn --arg s "$name.zip" '$s|@uri')"
else
  fname="$name.zip"
fi

resp="$(curl -fsS -X POST -H 'Content-Type: application/zip' --data-binary @"$tmpzip" "$UPLOAD_URL?filename=$fname")" \
  || { echo "error: upload failed ($UPLOAD_URL)" >&2; exit 1; }

if command -v jq >/dev/null 2>&1; then
  uid="$(printf '%s' "$resp" | jq -r '.upload_id // empty')"
else
  uid="$(printf '%s' "$resp" | grep -oE '"upload_id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]*)"$/\1/' || true)"
fi
[ -n "$uid" ] || { echo "error: no upload_id in response: $resp" >&2; exit 1; }

printf '%s\n' "$uid"   # stdout: just the id, easy to capture
echo "ok - pass upload_id=$uid to static_scan / scan_family" >&2
