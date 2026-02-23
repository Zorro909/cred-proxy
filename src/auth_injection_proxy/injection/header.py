"""Custom header injection."""

from __future__ import annotations

from mitmproxy import http


def inject_header(flow: http.HTTPFlow, header_name: str, header_value: str) -> list[str]:
    """Set a custom header. Returns list of injected secret values."""
    flow.request.headers[header_name] = header_value
    return [header_value]
