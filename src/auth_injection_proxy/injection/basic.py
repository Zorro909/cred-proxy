"""Basic auth injection."""

from __future__ import annotations

import base64

from mitmproxy import http


def inject_basic(flow: http.HTTPFlow, username: str, password: str) -> list[str]:
    """Set Authorization: Basic header. Returns list of injected secret values."""
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    flow.request.headers["Authorization"] = f"Basic {encoded}"
    return [encoded, password]
