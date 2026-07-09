"""FastAPI app factory and uvicorn entrypoint for the admin UI."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from deepscan_kruncher import db

from . import __version__, settings, static_dir
from .routes import router


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        db.close_pool()


def create_app() -> FastAPI:
    app = FastAPI(title="Deep Scan - Kruncher Admin", version=__version__, lifespan=_lifespan)
    app.include_router(router)
    app.mount("/", StaticFiles(directory=static_dir(), html=True), name="ui")
    return app


def main() -> None:
    """Console entrypoint: ``deepscan-kruncher-admin``."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    uvicorn.run(create_app(), host=settings.host(), port=settings.port())


if __name__ == "__main__":
    main()
