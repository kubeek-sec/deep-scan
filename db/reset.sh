#!/usr/bin/env bash
# DROP and recreate the database - destroys all scopes, jobs and findings.
# Requires confirmation: pass --yes or set DEEPSCAN_RESET_CONFIRM=yes.
set -euo pipefail
source "$(dirname "$0")/_env.sh"
require_psql

if [ "${1:-}" != "--yes" ] && [ "${DEEPSCAN_RESET_CONFIRM:-}" != "yes" ]; then
  read -r -p "This will DROP database '${DB_NAME}'. Type the name to confirm: " answer
  [ "$answer" = "$DB_NAME" ] || { echo "Aborted."; exit 1; }
fi

echo "==> Terminating connections to ${DB_NAME}"
psql "$ADMIN_URI" -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}' AND pid<>pg_backend_pid()" \
  >/dev/null || true
echo "==> Dropping and recreating ${DB_NAME}"
psql "$ADMIN_URI" -c "DROP DATABASE IF EXISTS \"${DB_NAME}\""
psql "$ADMIN_URI" -c "CREATE DATABASE \"${DB_NAME}\""
echo "==> Applying schema"
psql "$PSQL_URI" -v ON_ERROR_STOP=1 -f "${DB_DIR}/schema.sql"
echo "==> Reset complete."
