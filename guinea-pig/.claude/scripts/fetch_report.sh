#!/usr/bin/env bash
# Fetch a scan's report from the Deep Scan API (mirror of fetch_report.py / .ps1 -
# same CLI). Accepts a job id OR an upload_id, and can WAIT for a job still running.
# This is also the RECOVERY path after the MCP call drops with
# `MCP server "deepscan" session expired`: the scan keeps running server-side, so
# never re-upload / re-scan - just fetch it here (add --wait if it may still run).
#
#   fetch_report.sh N                     # report for Job #N to stdout (JSON)
#   fetch_report.sh N --format md         # markdown
#   fetch_report.sh <upload_id>           # newest job for that upload
#   fetch_report.sh <upload_id> --wait    # wait until that job is done, then fetch
#   fetch_report.sh N --wait --interval 15 --timeout 3600
#
# Needs: curl (plus jq for upload_id resolution and --wait). API base defaults to
# http://127.0.0.1:8800 (override with --base-url or DEEPSCAN_API_URL).
set -euo pipefail

BASE_URL="${DEEPSCAN_API_URL:-http://127.0.0.1:8800}"
FORMAT="json"
ID=""
WAIT=0
INTERVAL=15
TIMEOUT=3600

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2 ;;
    --format=*) FORMAT="${1#*=}"; shift ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --base-url=*) BASE_URL="${1#*=}"; shift ;;
    --wait) WAIT=1; shift ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --interval=*) INTERVAL="${1#*=}"; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --timeout=*) TIMEOUT="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "error: unknown option: $1" >&2; exit 2 ;;
    *) if [ -z "$ID" ]; then ID="$1"; else echo "error: unexpected arg: $1" >&2; exit 2; fi; shift ;;
  esac
done

[ -n "$ID" ] || { echo "error: job id or upload_id required" >&2; usage; exit 2; }
BASE_URL="${BASE_URL%/}"
have_jq() { command -v jq >/dev/null 2>&1; }

# Resolve an upload_id (anything non-numeric) to its NEWEST matching job id; a
# plain numeric id is used as the job id as-is.
JOB="$ID"
case "$ID" in
  ''|*[!0-9]*)
    have_jq || { echo "error: 'jq' needed to resolve an upload_id - or pass the numeric Job #N" >&2; exit 3; }
    JOB="$(curl -fsS -m 15 "$BASE_URL/api/scans" \
      | jq -r --arg u "$ID" '[.[] | select(.target|test($u))] | sort_by(.id) | last | .id // empty')"
    [ -n "$JOB" ] || { echo "error: no job found for upload_id '$ID'" >&2; exit 1; }
    echo "resolved upload_id '$ID' -> job #$JOB" >&2
    ;;
esac

# Optionally wait for the job to finish (the recovery path after a dropped session).
if [ "$WAIT" = "1" ]; then
  have_jq || { echo "error: 'jq' needed for --wait" >&2; exit 3; }
  echo "waiting for job #$JOB (every ${INTERVAL}s, up to ${TIMEOUT}s) …" >&2
  elapsed=0
  while :; do
    status="$(curl -fsS -m 15 "$BASE_URL/api/scans" | jq -r --argjson j "$JOB" '.[] | select(.id==$j) | .status // "unknown"')"
    case "$status" in
      done) echo "job #$JOB done" >&2; break ;;
      failed|error) echo "job #$JOB FAILED" >&2; exit 1 ;;
      *) echo "  … #$JOB $status [${elapsed}s]" >&2 ;;
    esac
    [ "$elapsed" -ge "$TIMEOUT" ] && { echo "error: timeout after ${TIMEOUT}s (job still $status)" >&2; exit 3; }
    sleep "$INTERVAL"; elapsed=$((elapsed + INTERVAL))
  done
fi

url="$BASE_URL/api/scans/$JOB/report?format=$FORMAT"
curl -fsS "$url" || { echo "error: could not fetch $url" >&2; exit 1; }
