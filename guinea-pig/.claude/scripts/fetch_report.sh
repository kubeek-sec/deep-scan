#!/usr/bin/env bash
# Fetch a finished scan's report from the Deep Scan API by job id (mirror of
# fetch_report.py - same CLI). The MCP scan tools print "Job #N"; pass N here.
#
#   fetch_report.sh N                       # JSON to stdout
#   fetch_report.sh N --format md           # markdown
#   fetch_report.sh N --base-url http://127.0.0.1:8800
#
# Needs: curl. The API base defaults to http://127.0.0.1:8800 (override with
# --base-url or DEEPSCAN_API_URL).
set -euo pipefail

BASE_URL="${DEEPSCAN_API_URL:-http://127.0.0.1:8800}"
FORMAT="json"
JOB=""

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2 ;;
    --format=*) FORMAT="${1#*=}"; shift ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --base-url=*) BASE_URL="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "error: unknown option: $1" >&2; exit 2 ;;
    *) if [ -z "$JOB" ]; then JOB="$1"; else echo "error: unexpected arg: $1" >&2; exit 2; fi; shift ;;
  esac
done

[ -n "$JOB" ] || { echo "error: job id required" >&2; usage; exit 2; }
BASE_URL="${BASE_URL%/}"
url="$BASE_URL/api/scans/$JOB/report?format=$FORMAT"
curl -fsS "$url" || { echo "error: could not fetch $url" >&2; exit 1; }
