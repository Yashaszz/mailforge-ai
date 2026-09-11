"""Vercel serverless entry point.

Vercel's Python runtime looks for an ASGI ``app`` in this module. The existing
FastAPI application is reused verbatim -- it already serves the dashboard and
the samples alongside the API, so one function covers the whole site and the
frontend keeps talking to its own origin with no configuration.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.main import app  # noqa: E402  (path must be set up first)

__all__ = ["app"]
