// CWE-78: OS Command Injection
// An untrusted program name flows through a helper into Command::new.
// Expected detecting family: sast
use std::process::Command;

fn run_cmd(prog: String) {
    // VULNERABLE SINK: the program to execute comes from untrusted input
    Command::new(prog).output().ok();
}

pub fn handle(input: String) {
    run_cmd(input);
}
