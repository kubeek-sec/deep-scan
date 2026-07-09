#!/usr/bin/env bash
# Scan a local directory with the Deep Scan docker image - no database and no
# kruncher fleet needed (a self-contained, one-off scan).
#
#   ./scan.sh <directory> [extra `deepscan scan` options...]
#
# Examples:
#   ./scan.sh ./my-project                      # full scan, all applicable scanners
#   ./scan.sh ./my-project --family sast --family secret
#   ./scan.sh ./my-project --scanner analysis   # fast, offline (code-graph taint)
#   ./scan.sh ./my-project --fail-on high       # exit 1 if a high+ finding (CI)
#   ./scan.sh ./my-project > report.md          # markdown report on stdout
#
# Reports (json/md/html/sarif/junit.xml + the interactive code graph under
# raw/graph.html) are written to ./deepscan-reports/scan-<timestamp>/ and owned
# by you (the scan runs as your uid, so nothing is left root-owned).
#
# AI triage (the `ai-analysis` scanner) needs the `claude` CLI INSIDE the image
# - the default image does NOT include it. Build one that does, once:
#   docker build -f deploy/docker/Dockerfile --build-arg INSTALL_CLAUDE=true \
#                -t kubeek-sec/deepscan:ai .
# then run with your model, e.g. a LOCAL model server on this host:
#   DEEPSCAN_IMAGE=kubeek-sec/deepscan:ai \
#   ANTHROPIC_BASE_URL=http://localhost:1234 ANTHROPIC_AUTH_TOKEN=local \
#   ANTHROPIC_MODEL=foundation-sec-8b \
#     ./scan.sh ./my-project --scanner ai-analysis
# (a localhost base-URL is auto-rewritten to host.docker.internal for the
# container; or use your key with ANTHROPIC_API_KEY). Your host's own `claude`
# binary is not used - it runs inside the container.
#
# Env overrides:
#   DEEPSCAN_IMAGE   image to run    (default: kubeek-sec/deepscan:latest)
#   DEEPSCAN_OUT     reports base    (default: ./deepscan-reports)
#   DEEPSCAN_CACHE   tool cache dir  (default: ~/.cache/deepscan-docker - persists
#                                     the opengrep engine so later runs are faster)
#   ANTHROPIC_* / DEEPSCAN_CLAUDE_SETTINGS  forwarded to the ai-analysis scanner
set -euo pipefail

IMAGE="${DEEPSCAN_IMAGE:-kubeek-sec/deepscan:latest}"

# Print the leading comment block (everything from line 2 to the first non-#).
usage() { awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; }

case "${1:-}" in
  "" | -h | --help) usage; exit 0 ;;
esac

TARGET=$1; shift
if [ ! -d "$TARGET" ]; then
  echo "error: '$TARGET' is not a directory." >&2
  exit 2
fi
TARGET=$(cd "$TARGET" && pwd)              # absolute path for the bind mount

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "error: docker image '$IMAGE' not found. Build it first:" >&2
  echo "  docker compose -f deploy/docker/docker-compose.yml build kruncher" >&2
  echo "(or set DEEPSCAN_IMAGE to an image you already have)" >&2
  exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
OUT="${DEEPSCAN_OUT:-$PWD/deepscan-reports}/scan-$STAMP"
CACHE="${DEEPSCAN_CACHE:-$HOME/.cache/deepscan-docker}"
mkdir -p "$OUT" "$CACHE"

# AI triage (the `ai-analysis` scanner) runs the `claude` CLI *inside* the image,
# so the image must be built with --build-arg INSTALL_CLAUDE=true. We forward
# your model/auth config so it uses YOUR model (a local model server on this host
# is reachable from the container at host.docker.internal - a localhost URL in
# ANTHROPIC_BASE_URL is rewritten to it automatically). Enable the scanner with
# `--scanner ai-analysis` (or AI_ANALYSIS=true for a full scan).
ai_args=()
for v in AI_ANALYSIS ANTHROPIC_BASE_URL ANTHROPIC_AUTH_TOKEN ANTHROPIC_API_KEY \
         ANTHROPIC_MODEL DEEPSCAN_CLAUDE_BIN DEEPSCAN_CLAUDE_MODEL; do
  val=$(printenv "$v" 2>/dev/null || true)
  [ -z "$val" ] && continue
  if [ "$v" = "ANTHROPIC_BASE_URL" ]; then
    val=${val//localhost/host.docker.internal}
    val=${val//127.0.0.1/host.docker.internal}
  fi
  ai_args+=( -e "$v=$val" )
done
# A claude settings file (e.g. for a local model - see
# deploy/docker/claude-settings.example.json) is mounted and forwarded.
if [ -n "${DEEPSCAN_CLAUDE_SETTINGS:-}" ] && [ -f "$DEEPSCAN_CLAUDE_SETTINGS" ]; then
  sdir=$(cd "$(dirname "$DEEPSCAN_CLAUDE_SETTINGS")" && pwd)
  ai_args+=( -v "$sdir/$(basename "$DEEPSCAN_CLAUDE_SETTINGS")":/claude-settings.json:ro \
             -e DEEPSCAN_CLAUDE_SETTINGS=/claude-settings.json )
fi

echo "▸ target : $TARGET" >&2
echo "▸ image  : $IMAGE"  >&2
echo "▸ reports: $OUT"    >&2
[ "${#ai_args[@]}" -gt 0 ] && echo "▸ ai     : forwarding model/auth config to the scanner" >&2

# Run as the invoking user so the reports are owned by you. The container's
# /tmp is world-writable (scratch/HOME), the engine cache is the mounted /cache,
# and DEEPSCAN_WAIT_FOR_DB=false stops the entrypoint waiting for Postgres.
run_args=(
  --rm
  --user "$(id -u):$(id -g)"
  --add-host host.docker.internal:host-gateway
  -v "$TARGET":/scan:ro
  -v "$OUT":/out
  -v "$CACHE":/cache
  -e DEEPSCAN_WAIT_FOR_DB=false
  -e HOME=/tmp -e TMPDIR=/tmp -e XDG_CACHE_HOME=/cache
)
run_args+=( "${ai_args[@]}" )

docker run "${run_args[@]}" "$IMAGE" \
  deepscan scan /scan --out /out --stdout md "$@"

echo "▸ reports written to $OUT" >&2
