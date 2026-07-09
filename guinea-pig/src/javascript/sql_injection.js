// CWE-89: SQL Injection
// User input is concatenated into a SQL query string before execution.
// Expected detecting family: sast

const db = require("mysql").createConnection({});

function getUser(req, res) {
  const id = req.query.id;
  // VULNERABLE SINK: query built with string concatenation
  db.query("SELECT * FROM users WHERE id = " + id, (err, rows) => {
    res.json(rows);
  });
}

function login(req, res) {
  // VULNERABLE SINK: template literal interpolates credentials into SQL
  const q = `SELECT * FROM users WHERE name = '${req.body.user}' AND pass = '${req.body.pass}'`;
  db.query(q, (err, rows) => res.json(rows));
}

module.exports = { getUser, login };
