# CWE-78: OS Command Injection
# User input flows into os.system and subprocess with shell=True.
# Expected detecting family: sast
import os
import subprocess


def ping(host):
    # VULNERABLE SINK: os.system with concatenated user input
    os.system("ping -c 1 " + host)


def backup(filename):
    # VULNERABLE SINK: subprocess with shell=True and interpolated input
    subprocess.call(f"tar czf /backups/{filename}.tgz /data", shell=True)


def run_report(name):
    # VULNERABLE SINK: shell=True on a built string
    return subprocess.check_output("generate_report " + name, shell=True)


if __name__ == "__main__":
    import sys
    ping(sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")
