#!/bin/sh
# Deep Scan - local single-host launcher.
#
# All config lives in deploy/docker/.env (copied from .env.example on first run
# below). Compose auto-loads it for both ${...} interpolation AND injects it into
# every app container, so that file is where you set POSTGRES_PASSWORD, connector
# tokens, the worker count (KRUNCHER_REPLICAS) and per-scanner toggles, e.g.:
#
#     CODEQL=false          # skip the slow CodeQL SAST scanner
#
# (toggle = SCANNER NAME in UPPERCASE, dashes -> underscores; see .env.example).
set -eu

# Run from the repo root regardless of where the script is invoked from, so the
# relative paths below resolve.
cd "$(dirname "$0")"

compose_file="deploy/docker/docker-compose.yml"
env_file="deploy/docker/.env"

# First run: seed .env from the example so the toggles/secrets have a home and
# --env-file has a file to read.
if [ ! -f "$env_file" ]; then
  echo "start.sh: $env_file not found - creating it from .env.example"
  cp "deploy/docker/.env.example" "$env_file"
fi

# No hardcoded --scale: the worker count comes from KRUNCHER_REPLICAS in .env
# (compose deploy.replicas), so .env stays the single source of truth. Override
# ad-hoc by passing extra args, e.g. `./start.sh --scale kruncher=8`.
docker compose --env-file "$env_file" -f "$compose_file" up --build "$@"


## Deep-scan ui http://127.0.0.1:8800/
## Deep-scan kruncher http://127.0.0.1:8900/
