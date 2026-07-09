// CWE-89 (patched): parameterized query, value bound out-of-band.
// The taint engine must NOT flag this: the SQL text is a constant literal and
// the untrusted value is passed as a positional parameter.
package store

import "database/sql"

func runQuery(db *sql.DB, id string) {
	// SAFE: constant SQL text + bound parameter ($1)
	db.Query("SELECT * FROM users WHERE id = $1", id)
}

func GetUser(db *sql.DB, id string) {
	runQuery(db, id)
}
