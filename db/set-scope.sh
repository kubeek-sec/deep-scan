#!/usr/bin/env bash
# Create or update a scope (upsert by name) with plain SQL - no Python needed.
#
# Usage:
#   db/set-scope.sh --name acme --connector github \
#       --config '{"org":"acme","token_env":"GITHUB_TOKEN"}' \
#       --families sast,secret --refresh 3600 --rescan 86400
#
#   db/set-scope.sh --name local --connector directory \
#       --config '{"base_path":"/data/projects"}'
#
# Equivalent to `deepscan-kruncher scope add`, for environments that only have
# psql. Connector is one of: github | gitlab | directory.
set -euo pipefail
source "$(dirname "$0")/_env.sh"
require_psql

NAME="" CONNECTOR="" CONFIG="{}" FAMILIES="" REFRESH=3600 RESCAN=86400 ENABLED=true
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2;;
    --connector) CONNECTOR="$2"; shift 2;;
    --config) CONFIG="$2"; shift 2;;
    --families) FAMILIES="$2"; shift 2;;
    --refresh) REFRESH="$2"; shift 2;;
    --rescan) RESCAN="$2"; shift 2;;
    --disabled) ENABLED=false; shift;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

[ -n "$NAME" ] && [ -n "$CONNECTOR" ] || { echo "--name and --connector are required" >&2; exit 2; }
case "$CONNECTOR" in github|gitlab|directory) ;; *) echo "connector must be github|gitlab|directory" >&2; exit 2;; esac

psql "$PSQL_URI" -v ON_ERROR_STOP=1 \
  -v name="$NAME" -v connector="$CONNECTOR" -v config="$CONFIG" \
  -v refresh="$REFRESH" -v rescan="$RESCAN" -v enabled="$ENABLED" -v families="$FAMILIES" <<'SQL'
INSERT INTO scopes (name, connector, config, enabled,
                    refresh_interval_seconds, rescan_interval_seconds, families)
VALUES (:'name', :'connector', :'config'::jsonb, :'enabled'::boolean,
        :'refresh'::int, :'rescan'::int,
        COALESCE(string_to_array(NULLIF(:'families',''), ','), '{}')::text[])
ON CONFLICT (name) DO UPDATE SET
    connector = EXCLUDED.connector,
    config = EXCLUDED.config,
    enabled = EXCLUDED.enabled,
    refresh_interval_seconds = EXCLUDED.refresh_interval_seconds,
    rescan_interval_seconds = EXCLUDED.rescan_interval_seconds,
    families = EXCLUDED.families,
    updated_at = now();
SELECT id, name, connector, enabled, families FROM scopes WHERE name = :'name';
SQL
echo "==> Scope '${NAME}' set. Run discovery with: deepscan-kruncher scope discover ${NAME}"
