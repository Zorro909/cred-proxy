"""Response credential stripping — replaces injected secrets with [REDACTED]."""

from __future__ import annotations

from mitmproxy import http

REDACTED = "[REDACTED]"


def strip_secrets(flow: http.HTTPFlow, injected_values: list[str]) -> None:
    """Replace any occurrence of injected secret values in response headers and body."""
    if not injected_values or not flow.response:
        return

    # Strip from response headers
    for name, value in list(flow.response.headers.items()):
        for secret in injected_values:
            if secret in value:
                flow.response.headers[name] = value.replace(secret, REDACTED)

    # Strip from response body
    if flow.response.content:
        body = flow.response.get_text(strict=False)
        if body:
            modified = body
            for secret in injected_values:
                if secret in modified:
                    modified = modified.replace(secret, REDACTED)
            if modified != body:
                flow.response.set_text(modified)
