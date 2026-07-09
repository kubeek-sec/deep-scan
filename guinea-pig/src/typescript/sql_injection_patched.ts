// CWE-89 (patched): parameterized query, value bound out-of-band.
// The taint engine must NOT flag this: the SQL text is a constant literal and
// the untrusted value is passed as a bound parameter.

interface Req {
  params: { id: string };
}

function loadUser(db: any, id: string) {
  // SAFE: constant SQL text + bound parameter
  db.query("SELECT * FROM users WHERE id = ?", [id]);
}

export function fetchUser(req: Req, db: any) {
  const id = req.params.id;
  loadUser(db, id);
}
