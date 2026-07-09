<?php
// CWE-78 (patched): argument escaped via escapeshellarg().
// The taint engine must NOT flag this: the tainted value passes through a
// sanitizer (escapeshellarg) before reaching system.

function runCommand($host) {
    // SAFE: escape the argument before it reaches the shell
    $safe = escapeshellarg($host);
    system("ping -c 1 " . $safe);
}

function handleRequest($host) {
    runCommand($host);
}
