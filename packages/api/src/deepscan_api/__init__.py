"""deepscan-api - REST API over the Deep Scan engine.

Accepts scan submissions (URL, git repository, local path or zip upload),
runs them through the shared Postgres-backed job store (``deepscan_jobs``) via
an in-process worker pool, and serves the generated reports plus the static
web app.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
