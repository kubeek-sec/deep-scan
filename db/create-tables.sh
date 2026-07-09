#!/usr/bin/env bash
# Apply (or re-apply) the schema to an existing database. Idempotent - safe to
# run after pulling schema changes.
set -euo pipefail
source "$(dirname "$0")/_env.sh"
require_psql
echo "==> Applying schema to ${DB_NAME}"
psql "$PSQL_URI" -v ON_ERROR_STOP=1 -f "${DB_DIR}/schema.sql"
echo "==> Done."
