// CWE-89: SQL Injection
// Request input flows through a helper into a concatenated SQL query.
// Expected detecting family: sast

interface Req {
  params: { id: string };
}

function loadUser(db: any, id: string) {
  // VULNERABLE SINK: query built by string concatenation
  db.query("SELECT * FROM users WHERE id = " + id);
}

export function fetchUser(req: Req, db: any) {
  const id = req.params.id; // untrusted source
  loadUser(db, id);
}
