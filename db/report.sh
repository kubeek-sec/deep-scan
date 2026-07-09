#!/usr/bin/env bash
# Run the analysis report.
#   db/report.sh              # run everything in reports.sql
#   db/report.sh posture      # run one named query (see `-- name:` tags)
#   db/report.sh --list       # list available query names
set -euo pipefail
source "$(dirname "$0")/_env.sh"
require_psql
SQL_FILE="${DB_DIR}/reports.sql"

if [ "${1:-}" = "--list" ]; then
  grep -oE '^-- name: .*' "$SQL_FILE" | sed 's/-- name: /  /'
  exit 0
fi

if [ -z "${1:-}" ]; then
  exec psql "$PSQL_URI" -v ON_ERROR_STOP=1 -f "$SQL_FILE"
fi

# Extract the single statement that follows `-- name: <arg>` up to its `;`.
QUERY="$(awk -v want="$1" '
  $0 ~ "^-- name: " want "$" { grab=1; next }
  grab && /^-- name: / { exit }
  grab { print; if ($0 ~ /;[[:space:]]*$/) exit }
' "$SQL_FILE")"

[ -n "$QUERY" ] || { echo "No query named '$1'. Try: db/report.sh --list" >&2; exit 2; }
psql "$PSQL_URI" -v ON_ERROR_STOP=1 -c "$QUERY"
