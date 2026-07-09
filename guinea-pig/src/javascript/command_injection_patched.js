// CWE-78 (patched): fixed program + argument array, no shell.
// The taint engine must NOT flag this: execFile takes a constant binary and an
// argument list, so untrusted input is never parsed by a shell.

const cp = require("child_process");

function runCommand(host) {
  // SAFE: no shell; the binary is constant and input is a plain argv entry
  cp.execFile("ping", ["-c", "1", host]);
}

function handlePing(req, res) {
  const host = req.query.host;
  runCommand(host);
}

module.exports = { handlePing };
