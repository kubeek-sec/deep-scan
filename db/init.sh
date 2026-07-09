#!/usr/bin/env bash
# Create the database (if missing) and apply the schema. Idempotent.
#
#   DEEPSCAN_DB_* env vars select the target (see db/_env.sh).
#   The connecting role must be allowed to CREATE DATABASE (or the DB must
#   already exist, in which case creation is skipped).
set -euo pipefail
source "$(dirname "$0")/_env.sh"
require_psql

echo "==> Ensuring database '${DB_NAME}' exists"
if psql "$ADMIN_URI" -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
  echo "    already present"
else
  psql "$ADMIN_URI" -c "CREATE DATABASE \"${DB_NAME}\""
  echo "    created"
fi

echo "==> Applying schema"
psql "$PSQL_URI" -v ON_ERROR_STOP=1 -f "${DB_DIR}/schema.sql"
echo "==> Done."
