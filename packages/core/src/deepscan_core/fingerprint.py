"""Stable, *verifiable* identity of a scanned directory.

Two complementary identifiers, both captured *before* the scan (on the RAM copy
when staged, so it is fast):

* :func:`fingerprint_tree` - a SHA-512 over **every** file in the tree (nothing
  excluded, ``.git`` history included). It is byte-for-byte reproducible with a
  standard shell one-liner so anyone can re-verify it on the source directory::

      find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha512sum | sha512sum

  (see :data:`VERIFY_COMMAND`). The digest is the SHA-512 of the concatenation,
  in ``LC_ALL=C`` path order, of each file's ``"<sha512>  ./<relpath>\\n"`` line
  - exactly what GNU coreutils ``sha512sum`` emits. So it covers both content
  and layout, and matches whether computed here or by hand.

* :func:`git_commit` - the checked-out commit when the source is a git work
  tree (``.git`` present). ``None`` otherwise - the content fingerprint is the
  fallback identity for that case.

The fingerprint is computed on the RAM scan copy, which is a full-fidelity copy
(:mod:`deepscan_jobs.ramfs` excludes nothing), so it equals the fingerprint of
the retained source directory the operator can re-hash by hand.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

_CHUNK = 1024 * 1024
_GIT_TIMEOUT = 10

#: The exact GNU-coreutils command (run from *inside* the directory) that
#: reproduces :func:`fingerprint_tree`'s digest. Documented in reports so the
#: fingerprint can be re-verified by hand.
VERIFY_COMMAND = (
    "find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha512sum | sha512sum"
)


def fingerprint_tree(root: str | os.PathLike[str]) -> str | None:
    """Verifiable content+layout SHA-512 of ``root`` (``"sha512:<hex>"``) or ``None``.

    Mirrors :data:`VERIFY_COMMAND`: every regular file (symlinks skipped, like
    ``find -type f``) contributes one ``"<file-sha512>  ./<relpath>\\n"`` line, in
    ``LC_ALL=C`` byte order of the ``./``-prefixed path, and the digest is the
    SHA-512 of those lines concatenated. Nothing is excluded - ``.git`` and all.

    Returns ``None`` when ``root`` is not a directory; unreadable files are
    skipped (as ``sha512sum`` would, producing no line for them) so one bad file
    never aborts the fingerprint. NB: paths containing newlines or backslashes
    are not covered by the plain shell command (``sha512sum`` escapes those) and
    are the one case where hand-verification can differ.
    """
    base = Path(root)
    if not base.is_dir():
        return None
    final = hashlib.sha512()
    # Sort by the './'-prefixed name. Python sorts str by code point; for UTF-8
    # that equals LC_ALL=C byte order, so this matches `sort -z`.
    for name in sorted(_rel_names(base)):
        file_hex = _file_sha512(base / name[2:])  # name is "./<relpath>"
        if file_hex is None:
            continue
        final.update(f"{file_hex}  {name}\n".encode("utf-8", "surrogatepass"))
    return f"sha512:{final.hexdigest()}"


def _rel_names(root: Path):
    """Yield ``"./<relpath>"`` for every regular file (no symlinks), like ``find .``."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                stack.append(Path(entry.path))
            elif entry.is_file(follow_symlinks=False):
                yield "./" + Path(entry.path).relative_to(root).as_posix()


def _file_sha512(path: Path) -> str | None:
    h = hashlib.sha512()
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def git_commit(root: str | os.PathLike[str]) -> str | None:
    """The checked-out commit SHA of the git work tree at ``root``, or ``None``.

    ``None`` when ``root`` is not a git repository, git is unavailable, or the
    command fails - never raises. (Read from the *original* source, not a RAM
    copy: the commit identifies the .git history independently of the file hash.)
    """
    base = Path(root)
    if not (base / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(base), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = result.stdout.strip()
    if result.returncode == 0 and len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
        return sha
    return None
