<?php
// CWE-78: OS Command Injection
// Untrusted input flows through a helper into system().
// Expected detecting family: sast

function runCommand($cmd) {
    // VULNERABLE SINK: shell command from untrusted input
    system($cmd);
}

function handleRequest($host) {
    runCommand("ping -c 1 " . $host);
}
