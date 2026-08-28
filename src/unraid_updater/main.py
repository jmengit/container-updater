"""Application entry point."""
from __future__ import annotations

import uvicorn

from .web import create_app

app = create_app()


def run() -> None:
    uvicorn.run("unraid_updater.main:app", host="0.0.0.0", port=8080, proxy_headers=False)