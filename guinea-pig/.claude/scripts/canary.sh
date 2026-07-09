#!/usr/bin/env bash
# Controlled, owner-operated canary endpoints for security evaluation (mirror of
# canary.py - same CLI). Inert kubeek.com endpoints used only to validate
# drop/exfiltration/info-collection paths; the ONLY external host an evaluation,
# demo or non-regression test may contact. See ../canary-endpoints.md.
#
#   canary.sh info [--method GET|POST]
#   canary.sh monip
#   canary.sh download  run.sh|run.ps1|run.txt   # via /run/download.php?file=
#   canary.sh direct    run.sh|run.ps1|run.txt   # via /run/<file>
#   canary.sh download2 a|b|c                     # a=run.sh b=run.ps1 c=run.txt
#
# Needs: curl. Env: KUBEEK_BASE_URL (default https://kubeek.com),
# KUBEEK_USER_AGENT (Cloudflare 403s an empty UA, so one is always sent).
set -euo pipefail

BASE_URL="${KUBEEK_BASE_URL:-https://kubeek.com}"; BASE_URL="${BASE_URL%/}"
USER_AGENT="${KUBEEK_USER_AGENT:-deepscan-security-eval/1.0}"
FILES="run.sh run.ps1 run.txt"

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//' >&2
}

req() { # method url
  if [ "$1" = "GET" ]; then
    curl -fsS -A "$USER_AGENT" "$2"
  else
    # Cloudflare 403s a bodyless POST (no Content-Length); send an empty body so
    # a "Content-Length: 0" is present.
    curl -fsS -A "$USER_AGENT" -X "$1" --data '' "$2"
  fi
}

valid_file() { case " $FILES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

cmd="${1:-}"; [ $# -gt 0 ] && shift || true
case "$cmd" in
  info)
    method=GET
    while [ $# -gt 0 ]; do
      case "$1" in
        --method) method="$2"; shift 2 ;;
        --method=*) method="${1#*=}"; shift ;;
        *) echo "error: unknown arg: $1" >&2; exit 2 ;;
      esac
    done
    # /info 301-redirects to /info/, and following a 301 downgrades POST->GET,
    # corrupting the method echo - so target the trailing-slash form directly.
    req "$method" "$BASE_URL/info/"
    ;;
  monip)
    req GET "$BASE_URL/monip/"
    ;;
  download)
    f="${1:-}"; valid_file "$f" || { echo "error: file must be one of: $FILES" >&2; exit 2; }
    req GET "$BASE_URL/run/download.php?file=$f"
    ;;
  direct)
    f="${1:-}"; valid_file "$f" || { echo "error: file must be one of: $FILES" >&2; exit 2; }
    req GET "$BASE_URL/run/$f"
    ;;
  download2)
    a="${1:-}"; case "$a" in a|b|c) ;; *) echo "error: attribut must be a|b|c" >&2; exit 2 ;; esac
    req GET "$BASE_URL/run/download2.php?attribut=$a"
    ;;
  ""|-h|--help|help)
    usage
    ;;
  *)
    echo "error: unknown command: $cmd" >&2; usage; exit 2
    ;;
esac
