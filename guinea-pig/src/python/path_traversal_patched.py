# CWE-22: Path Traversal - PATCHED (false-positive trap / negative control)
# Resolves the real path and confirms containment in BASE_DIR before opening.
# Expected detecting family: sast (expected result: no finding)
import os

BASE_DIR = "/var/www/files"


def read_file(user_path):
    # FIXED: normalize and confirm the resolved path stays within BASE_DIR
    full = os.path.realpath(os.path.join(BASE_DIR, user_path))
    if not full.startswith(os.path.realpath(BASE_DIR) + os.sep):
        raise ValueError("path traversal attempt blocked")
    with open(full, "r") as f:
        return f.read()


if __name__ == "__main__":
    import sys
    print(read_file(sys.argv[1] if len(sys.argv) > 1 else "readme.txt"))
