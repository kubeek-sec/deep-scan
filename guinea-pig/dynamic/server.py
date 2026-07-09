#!/usr/bin/env python3
# CWE-79, CWE-89, CWE-78, CWE-22, CWE-601, CWE-918, CWE-209, CWE-614, CWE-942, CWE-693
# Deliberately-vulnerable HTTP target for DAST scanning. Standard library ONLY.
# Bind: 0.0.0.0:4000  (loopback only). Run: python3 dynamic/server.py
# Expected detecting family: dast
#
# ISOLATION WARNING: every route is intentionally exploitable. Run ONLY on
# loopback, never expose to a network, seed no real data, tear down after scan.

import os
import sqlite3
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HOST = "0.0.0.0"
PORT = 4000


def seed_db():
    # In-memory SQLite seeded with throwaway dummy users (no real data).
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
    cur.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [
            (1, "alice", "alice@example.com"),
            (2, "bob", "bob@example.com"),
            (3, "carol", "carol@example.com"),
        ],
    )
    conn.commit()
    return conn


DB = seed_db()


class Handler(BaseHTTPRequestHandler):
    server_version = "GuineaPigDAST/1.0"

    def _send(self, code, body, content_type="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # CWE-942: wildcard CORS origin combined with credentials.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        # CWE-693: NO security headers anywhere (no CSP, X-Frame-Options,
        # X-Content-Type-Options, HSTS) so baseline DAST checks fire.
        for k, v in (extra_headers or {}):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/":
            return self._send(200, "<h1>Guinea Pig DAST target</h1>")

        if path == "/search":
            # CWE-79: reflected XSS - q echoed into HTML unescaped.
            q = qs.get("q", [""])[0]
            return self._send(200, "<p>Results for: " + q + "</p>")

        if path == "/users":
            # CWE-89 + CWE-209: id concatenated into SQL; raw error leaked.
            uid = qs.get("id", [""])[0]
            try:
                cur = DB.cursor()
                cur.execute("SELECT id, name, email FROM users WHERE id = " + uid)
                rows = cur.fetchall()
                return self._send(200, "<pre>" + str(rows) + "</pre>")
            except Exception as e:
                # CWE-209: verbose SQL error disclosed to the client.
                return self._send(500, "SQL error: " + repr(e))

        if path == "/ping":
            # CWE-78: command injection via os.popen on user host.
            host = qs.get("host", ["127.0.0.1"])[0]
            output = os.popen("ping -c 1 " + host).read()
            return self._send(200, "<pre>" + output + "</pre>")

        if path == "/download":
            # CWE-22: path traversal - file opened from a user path.
            name = qs.get("file", ["readme.txt"])[0]
            try:
                with open("/var/www/files/" + name, "rb") as f:
                    return self._send(200, f.read(), "application/octet-stream")
            except Exception as e:
                return self._send(404, "not found: " + repr(e))

        if path == "/redirect":
            # CWE-601: open redirect - Location taken from user input.
            target = qs.get("url", ["/"])[0]
            return self._send(302, "", extra_headers=[("Location", target)])

        if path == "/fetch":
            # CWE-918: SSRF - server fetches an attacker-controlled URL.
            url = qs.get("url", ["https://kubeek.com/info/"])[0]
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    return self._send(200, resp.read(), "text/plain")
            except Exception as e:
                return self._send(502, "fetch error: " + repr(e))

        if path == "/set-cookie":
            # CWE-614/CWE-1004: session cookie without HttpOnly/Secure/SameSite.
            return self._send(
                200,
                "cookie set",
                extra_headers=[("Set-Cookie", "session=abc123def456; Path=/")],
            )

        return self._send(404, "<p>not found</p>")

    def log_message(self, fmt, *args):
        pass  # quiet


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Guinea Pig DAST target listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
