"""The ops copy of the schema (db/schema.sql) must match the packaged one."""

from __future__ import annotations

from pathlib import Path

from deepscan_jobs import db

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_db_schema_matches_packaged_schema():
    ops_copy = (REPO_ROOT / "db" / "schema.sql").read_text(encoding="utf-8")
    assert ops_copy == db.schema_sql(), (
        "db/schema.sql is out of sync with the packaged schema. "
        "Regenerate with: deepscan-kruncher db dump-schema > db/schema.sql"
    )
