"""Bearer token injection."""

from __future__ import annotations

from mitmproxy import http


def inject_bearer(flow: http.HTTPFlow, token: str) -> list[str]:
    """Set Authorization: Bearer header. Returns list of injected secret values."""
    flow.request.headers["Authorization"] = f"Bearer {token}"
    return [token]
