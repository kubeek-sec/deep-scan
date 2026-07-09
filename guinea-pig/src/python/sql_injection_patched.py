# CWE-89: SQL Injection - PATCHED (false-positive trap / negative control)
# Uses parameterized queries; scanners should NOT flag this file.
# Expected detecting family: sast (expected result: no finding)
import sqlite3


def get_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # FIXED: bound parameter
    cur.execute("SELECT id, name, email FROM users WHERE username = ?", (username,))
    return cur.fetchall()


def search_products(term):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # FIXED: bound parameter with wildcards added to the value
    cur.execute("SELECT * FROM products WHERE name LIKE ?", ("%" + term + "%",))
    return cur.fetchall()


if __name__ == "__main__":
    import sys
    print(get_user(sys.argv[1] if len(sys.argv) > 1 else "admin"))
