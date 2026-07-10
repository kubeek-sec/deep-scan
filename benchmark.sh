#!/usr/bin/env bash
# Launch the benchmark scan matrix (10 languages x 3 complexity tiers) via the
# manual API. Thin wrapper around tests/scan_benchmark.py - every flag of that
# script passes straight through.
#
#   ./benchmark.sh                          # submit all 30 repos, don't wait
#   ./benchmark.sh --lang python,go --wait  # only Python + Go, wait for results
#   ./benchmark.sh --tier simple --families sca   # just the small repos, SCA only
#   ./benchmark.sh --dry-run                # preview what would be sent
#   ./benchmark.sh --help                   # full flag list
#
# The API must be running (./start.sh) unless you pass --dry-run/--help. Point at
# a different endpoint with DEEPSCAN_API_URL (default http://localhost:8800).
set -euo pipefail

# Run from the repo root regardless of where it is invoked from.
cd "$(dirname "$0")"

API="${DEEPSCAN_API_URL:-http://localhost:8800}"

# Friendly heads-up if the API is down (skip the check for dry-run/help).
case " $* " in
  *" --dry-run "* | *" -h "* | *" --help "*) ;;
  *)
    if ! curl -fsS -o /dev/null --max-time 3 "$API/api/healthz" 2>/dev/null; then
      echo "warning: API not reachable at $API - start the stack with ./start.sh" >&2
      echo "         (or pass --dry-run to preview, or set DEEPSCAN_API_URL)" >&2
    fi
    ;;
esac

exec python3 tests/scan_benchmark.py "$@"
