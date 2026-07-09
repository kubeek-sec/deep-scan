# CWE-89: SQL Injection
# User input is concatenated directly into a SQL string and executed via sqlite3.
# Expected detecting family: sast
import sqlite3


def get_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULNERABLE SINK: string concatenation builds the query
    query = "SELECT id, name, email FROM users WHERE username = '" + username + "'"
    cur.execute(query)
    return cur.fetchall()


def search_products(term):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULNERABLE SINK: f-string interpolation into SQL
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return cur.fetchall()


if __name__ == "__main__":
    import sys
    print(get_user(sys.argv[1] if len(sys.argv) > 1 else "admin"))
