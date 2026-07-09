#!/usr/bin/env bash
# Container entrypoint: optionally wait for Postgres and apply the schema, then
# exec the requested command. Controlled by env so the same image fits every
# role and both compose/k8s.
#
#   DEEPSCAN_WAIT_FOR_DB=true   block until Postgres answers (default true)
#   DEEPSCAN_DB_MIGRATE=false   run `deepscan-kruncher db init` first (default false;
#                               turn on for exactly one bootstrap container)
set -euo pipefail

# Under a read-only rootfs the only writable paths are mounted volumes/tmpfs.
# Deployments point TMPDIR / XDG_CACHE_HOME at a big writable volume (e.g. /work)
# so the scanners' scratch (CodeQL DBs, ClamAV unpack) and self-extracting
# engines (opengrep) don't fill the tiny /tmp tmpfs or hit the read-only FS.
#
# CRITICAL: Python's tempfile silently IGNORES $TMPDIR if the dir is missing or
# unwritable and falls back to /tmp - which would quietly reintroduce the
# "No space left on device" failures. So create the dirs here (we run as the app
# user, before any command) and warn loudly if they aren't writable.
ensure_dir() {
  [ -n "${1:-}" ] || return 0
  if ! mkdir -p "$1" 2>/dev/null || [ ! -w "$1" ]; then
    echo "entrypoint: WARNING: '$1' is not writable - scanners will fall back to" \
         "/tmp and large scans (CodeQL/ClamAV) may fail with 'No space left on device'." >&2
  fi
}
ensure_dir "${TMPDIR:-}"
ensure_dir "${XDG_CACHE_HOME:-}"

wait_for_db() {
  echo "entrypoint: waiting for database…"
  for _ in $(seq 1 60); do
    if deepscan-kruncher db check >/dev/null 2>&1; then
      echo "entrypoint: database is up."
      return 0
    fi
    sleep 2
  done
  echo "entrypoint: database not reachable after timeout" >&2
  return 1
}

if [ "${DEEPSCAN_WAIT_FOR_DB:-true}" = "true" ]; then
  wait_for_db
fi

if [ "${DEEPSCAN_DB_MIGRATE:-false}" = "true" ]; then
  echo "entrypoint: applying schema…"
  deepscan-kruncher db init
fi

exec "$@"
