// CWE-78: OS Command Injection
// Untrusted request input flows through a helper into child_process.exec.
// Expected detecting family: sast

const cp = require("child_process");

function runCommand(cmd) {
  // VULNERABLE SINK: shell command string built from untrusted input
  cp.exec(cmd);
}

function handlePing(req, res) {
  const host = req.query.host; // untrusted source
  runCommand("ping -c 1 " + host);
}

module.exports = { handlePing };
