# Dynamic (DAST) target

A deliberately-vulnerable HTTP service using **only the Python standard library**
(`http.server`). It is the live target for dynamic application security testing.

## Run

```bash
python3 dynamic/server.py
```

It binds **127.0.0.1:3000** (loopback only) and seeds an in-memory SQLite table
with three throwaway dummy users. Zero dependencies.

## Isolation warnings

- **Loopback only.** The server binds `127.0.0.1`. Never change the bind address,
  port-forward it, or place it behind a public proxy. Every route is exploitable.
- **No real data.** The SQLite DB is in-memory and seeded with fake users. Do not
  point it at any real database or credential.
- **Tear down after scanning.** Stop the process (Ctrl-C) as soon as the scan
  finishes; do not leave it running.

## Routes (each maps to a ground-truth finding in `expected_findings.json`)

| Route | Vuln | CWE |
|---|---|---|
| `/search?q=` | Reflected XSS | CWE-79 |
| `/users?id=` | SQL injection + verbose SQL error | CWE-89, CWE-209 |
| `/ping?host=` | OS command injection (`os.popen`) | CWE-78 |
| `/download?file=` | Path traversal | CWE-22 |
| `/redirect?url=` | Open redirect | CWE-601 |
| `/fetch?url=` | SSRF (`urllib`) | CWE-918 |
| `/set-cookie` | Session cookie missing HttpOnly/Secure/SameSite | CWE-614, CWE-1004 |
| (all responses) | CORS `*` + `Allow-Credentials: true` | CWE-942 |
| (all responses) | No CSP / X-Frame-Options / nosniff / HSTS | CWE-693 |

## Quick manual proof

```bash
curl 'http://127.0.0.1:3000/search?q=<script>alert(1)</script>'   # reflected unescaped
curl 'http://127.0.0.1:3000/users?id=1'                            # normal row
curl "http://127.0.0.1:3000/users?id=1 OR 1=1"                     # injection
curl "http://127.0.0.1:3000/users?id=abc"                          # verbose SQL error
curl -i 'http://127.0.0.1:3000/redirect?url=http://evil.example'   # 302 Location echoes input
```
