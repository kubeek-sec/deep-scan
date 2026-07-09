# Canary endpoints - the only external addresses allowed in an evaluation

Deep Scan audits code and writes non-regression tests. To **validate** that a
finding is real and that a fix actually contains it - without ever touching real
attacker infrastructure - evaluations, demonstrations and tests may contact
**only** the controlled, owner-operated canary endpoints below. They live on
**`kubeek.com`**, a domain the project owner controls and monitors, and they are
**inert**: they exist solely to confirm a *capability* (outbound HTTP, info
collection, IP echo, file "drop"/download) against a benign, owned target.

> **Rule for every security skill/command here:** any request that leaves the
> machine must go to a `kubeek.com` endpoint listed below - nothing else. The
> scripts these endpoints serve are **not** malicious; they only let us prove a
> drop/exfiltration/info-collection path exists (before the fix) and is closed
> (after the fix).

Prefer the **canary helper** over hand-rolled calls so tests can only ever hit
these endpoints. It ships in three interchangeable forms with the same CLI -
[`scripts/canary.sh`](scripts/canary.sh) (Linux/macOS),
[`scripts/canary.ps1`](scripts/canary.ps1) (Windows) and
[`scripts/canary.py`](scripts/canary.py) (fallback); pick the form for your OS
(see [`scripts/README.md`](scripts/README.md)). Base URL defaults to
`https://kubeek.com` (override with `KUBEEK_BASE_URL`).

## Cloudflare / User-Agent

The site is fronted by Cloudflare, which **rejects requests with no
User-Agent**. Always send one. `canary.py` sets
`deepscan-security-eval/1.0` (override with
`KUBEEK_USER_AGENT`); with `curl`, pass `-A`.

## Endpoints

| Purpose | Endpoint | Notes |
|---|---|---|
| **Method / reachability echo** | `GET\|POST /info/` | Returns the HTTP method used with an `ok` status - a simple outbound-HTTP beacon. Keep the **trailing slash**: `/info` 301-redirects to `/info/`, and a followed 301 downgrades POST→GET. |
| **Origin IP / info collection** | `GET /monip/` | JSON: the request's origin IP as seen across several headers (`X-Forwarded-For`, `CF-Connecting-IP`, `REMOTE_ADDR`). Use to validate IP/info exfiltration paths. |
| **Drop via PHP (by name)** | `GET /run/download.php?file=run.sh` | `file` ∈ `run.sh` · `run.ps1` · `run.txt`. **Needs a User-Agent.** |
| **Drop, direct file** | `GET /run/run.sh` | Also `/run/run.ps1`, `/run/run.txt`. Direct download of the inert script. |
| **Drop via PHP (by code)** | `GET /run/download2.php?attribut=a` | `a` → `run.sh`, `b` → `run.ps1`, `c` → `run.txt`. |

The served scripts are inert (`run.sh`/`run.txt`: `echo "It runs!"`;
`run.ps1`: `Write-Host "It runs!"`). A request with **no** User-Agent is
rejected by Cloudflare with **403** - always send one.

The `run.sh` / `run.ps1` / `run.txt` files are inert staging artifacts used to
demonstrate a "drop" (fetch-and-stage) capability across shells/OSes; they
perform nothing harmful.

## Quick reference

```bash
# Via the helper (preferred - it always sends a User-Agent and stays on-domain).
# Linux/macOS uses canary.sh; on Windows use `pwsh -File .../canary.ps1 <args>`,
# fallback `python3 .../canary.py <args>` - all take the same subcommands:
bash .claude/scripts/canary.sh info                 # GET  /info/
bash .claude/scripts/canary.sh info --method POST   # POST /info/
bash .claude/scripts/canary.sh monip                # GET  /monip/
bash .claude/scripts/canary.sh download  run.sh     # GET  /run/download.php?file=run.sh
bash .claude/scripts/canary.sh direct    run.ps1    # GET  /run/run.ps1
bash .claude/scripts/canary.sh download2 a          # GET  /run/download2.php?attribut=a

# Equivalent raw curl (note the mandatory -A user-agent, and trailing slashes):
UA='deepscan-security-eval/1.0'
curl -fsS -A "$UA" https://kubeek.com/info/
curl -fsS -A "$UA" https://kubeek.com/monip/
curl -fsS -A "$UA" 'https://kubeek.com/run/download.php?file=run.sh'
curl -fsS -A "$UA" https://kubeek.com/run/run.sh
curl -fsS -A "$UA" 'https://kubeek.com/run/download2.php?attribut=a'
```

```python
# From a non-regression test:
import sys; sys.path.insert(0, ".claude/scripts")
import canary

status, body = canary.monip()          # validate the IP-exfil path is reachable...
assert status == 200
# ...then assert the FIXED code path never calls canary.* (e.g. the sanitizer
# strips the user-controlled URL, so no outbound request is made).
```
