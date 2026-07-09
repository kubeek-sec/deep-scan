"""Zip-upload staging for the API and the MCP http transport.

A zip already streamed to disk is safely extracted once into
``<data_dir>/uploads/<id>`` (via ``deepscan_core.targets.extract_zip``) and
recorded; an ad-hoc ``zip`` job then references that directory by ``target``.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from deepscan_core.targets import extract_zip

from . import config, db


def uploads_dir() -> Path:
    d = config.data_dir() / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    return d


def stage_zip(archive_path: str | Path, filename: str | None = None) -> dict[str, Any]:
    """Extract a zip already on disk into ``uploads/<id>``; record and return it.

    Raises ``deepscan_core.targets.TargetError`` on an invalid/unsafe archive.
    """
    upload_id = uuid.uuid4().hex
    dest = uploads_dir() / upload_id
    extract_zip(Path(archive_path), dest)
    with db.connection() as conn:
        row = conn.execute(
            "INSERT INTO uploads (id, path, filename) VALUES (%s, %s, %s) RETURNING *",
            (upload_id, str(dest), filename),
        ).fetchone()
        conn.commit()
    return row


def resolve_upload(upload_id: str) -> str | None:
    row = db.fetchone("SELECT path FROM uploads WHERE id = %s", (upload_id,))
    return row["path"] if row else None


def get_upload(upload_id: str) -> dict[str, Any] | None:
    """The full upload row (``id``, ``path``, ``filename``, ``created_at``)."""
    return db.fetchone("SELECT * FROM uploads WHERE id = %s", (upload_id,))


def delete_upload(upload_id: str) -> None:
    db.execute("DELETE FROM uploads WHERE id = %s", (upload_id,))
