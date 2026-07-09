"""FastAPI app factory and uvicorn entrypoint.

The API is a *submitter*, not an executor: a scan posted here becomes a queued
``origin='adhoc'`` (manual queue) job in the shared Postgres store
(``deepscan_jobs``), and the **kruncher worker fleet** runs it - the same fleet
that runs periodic scans. The API only validates input, enqueues, and serves
results/reports. The static web app is mounted at ``/`` after the API routes so
``/api/*`` always wins.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import deepscan_web
from deepscan_jobs import db as jobs_db

from . import __version__, settings
from .routes import router


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    from deepscan_core.log import setup_logging

    setup_logging()
    jobs_db.init_schema()  # idempotent; a no-op once the shared schema exists
    try:
        yield
    finally:
        jobs_db.close_pool()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Deep Scan API",
        version=__version__,
        lifespan=_lifespan,
    )
    app.include_router(router)
    app.mount(
        "/",
        StaticFiles(directory=deepscan_web.static_dir(), html=True),
        name="web",
    )
    return app


def main() -> None:
    """Console entrypoint: ``deepscan-api``."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    uvicorn.run(create_app(), host=settings.host(), port=settings.port())


if __name__ == "__main__":
    main()
