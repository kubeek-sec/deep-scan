# CWE-78: OS Command Injection - PATCHED (false-positive trap / negative control)
# Uses argument lists (no shell) and shlex.quote; scanners should NOT flag this.
# Expected detecting family: sast (expected result: no finding)
import shlex
import subprocess


def ping(host):
    # FIXED: argument list, no shell
    subprocess.run(["ping", "-c", "1", host], check=True)


def backup(filename):
    # FIXED: argument list, no shell interpolation
    safe = shlex.quote(filename)
    subprocess.run(["tar", "czf", f"/backups/{safe}.tgz", "/data"], check=True)


def run_report(name):
    # FIXED: argument list, no shell
    return subprocess.check_output(["generate_report", name])


if __name__ == "__main__":
    import sys
    ping(sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")
