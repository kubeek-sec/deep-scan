# CWE-22: Path Traversal
# User-controlled path is passed to open() without normalization or containment.
# Expected detecting family: sast
import os

BASE_DIR = "/var/www/files"


def read_file(user_path):
    # VULNERABLE SINK: user path joined and opened, allows ../../ escape
    full = os.path.join(BASE_DIR, user_path)
    with open(full, "r") as f:
        return f.read()


def serve_download(filename):
    # VULNERABLE SINK: direct open of attacker-controlled filename
    return open("/var/www/files/" + filename, "rb").read()


if __name__ == "__main__":
    import sys
    print(read_file(sys.argv[1] if len(sys.argv) > 1 else "readme.txt"))
