// CWE-601: URL Redirection to Untrusted Site (Open Redirect)
// A user-supplied URL is used directly as a redirect target.
// Expected detecting family: sast

function goto(req, res) {
  // VULNERABLE SINK: unvalidated user input used as redirect location
  res.redirect(req.query.url);
}

function logoutRedirect(req, res) {
  // VULNERABLE SINK: next param echoed into Location header without allowlist
  res.writeHead(302, { Location: req.query.next });
  res.end();
}

module.exports = { goto, logoutRedirect };
