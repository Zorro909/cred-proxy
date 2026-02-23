"""Query parameter injection."""

from __future__ import annotations

from mitmproxy import http


def inject_query_param(flow: http.HTTPFlow, param_name: str, param_value: str) -> list[str]:
    """Set/replace a query parameter. Returns list of injected secret values."""
    flow.request.query[param_name] = param_value
    return [param_value]
