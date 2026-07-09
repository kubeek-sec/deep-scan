#!/usr/bin/env bash
# Shared connection resolver for the db/ scripts. Source it, then use $PSQL_URI.
#
# Precedence: DEEPSCAN_DB_DSN / DATABASE_URL win; otherwise assembled from the
# DEEPSCAN_DB_* parts (the same ones the kruncher reads), with libpq defaults.
set -euo pipefail

DB_HOST="${DEEPSCAN_DB_HOST:-${PGHOST:-localhost}}"
DB_PORT="${DEEPSCAN_DB_PORT:-${PGPORT:-5432}}"
DB_NAME="${DEEPSCAN_DB_NAME:-${PGDATABASE:-deepscan}}"
DB_USER="${DEEPSCAN_DB_USER:-${PGUSER:-deepscan}}"
DB_PASSWORD="${DEEPSCAN_DB_PASSWORD:-${PGPASSWORD:-deepscan}}"

# A maintenance URI on the 'postgres' database, for create/drop operations.
ADMIN_DB="${DEEPSCAN_ADMIN_DB:-postgres}"

if [ -n "${DEEPSCAN_DB_DSN:-}" ]; then
  PSQL_URI="$DEEPSCAN_DB_DSN"
elif [ -n "${DATABASE_URL:-}" ]; then
  PSQL_URI="$DATABASE_URL"
else
  PSQL_URI="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
fi
ADMIN_URI="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${ADMIN_DB}"

export PSQL_URI ADMIN_URI DB_NAME DB_USER
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DB_DIR="$HERE"

require_psql() {
  command -v psql >/dev/null 2>&1 || {
    echo "psql not found. Install postgresql-client or run inside the postgres container." >&2
    exit 1
  }
}
