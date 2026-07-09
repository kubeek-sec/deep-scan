// CWE-89: SQL Injection
// An untrusted id flows through a helper into a concatenated db.Query call.
// Expected detecting family: sast
package store

import "database/sql"

func runQuery(db *sql.DB, id string) {
	// VULNERABLE SINK: query built by string concatenation
	db.Query("SELECT * FROM users WHERE id = " + id)
}

// GetUser passes an untrusted id into the query helper.
func GetUser(db *sql.DB, id string) {
	runQuery(db, id)
}
