// CWE-78 (patched): fixed program; untrusted value passed only as an argument.
// The taint engine must NOT flag this: Command::new gets a constant binary, so
// the untrusted value is a plain argument and cannot change which program runs.
use std::process::Command;

fn run_cmd(arg: String) {
    // SAFE: constant program; user data is an argv entry, not the command
    Command::new("echo").arg(arg).output().ok();
}

pub fn handle(input: String) {
    run_cmd(input);
}
