"""Agent-facing /__auth/* request handlers integrated into mitmproxy."""

from __future__ import annotations

import json
import logging
import re

from mitmproxy import http

from auth_injection_proxy.access.store import AccessRuleStore
from auth_injection_proxy.requests.pending import PendingRequestStore
from auth_injection_proxy.store.interface import CredentialStore

logger = logging.getLogger(__name__)

VALID_AUTH_TYPES = {"bearer", "basic", "header", "query_param", "oauth2_client_credentials"}
DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
)


class AgentApiHandler:
    def __init__(
        self,
        store: CredentialStore,
        pending: PendingRequestStore,
        mgmt_port: int = 8081,
        access_store: AccessRuleStore | None = None,
    ) -> None:
        self._store = store
        self._pending = pending
        self._mgmt_port = mgmt_port
        self._access_store = access_store

    async def handle(self, flow: http.HTTPFlow) -> bool:
        """Handle /__auth/* requests. Returns True if handled, False otherwise."""
        path = flow.request.path.split("?")[0]
        if not path.startswith("/__auth/"):
            return False

        if path == "/__auth/credentials":
            await self._handle_list_credentials(flow)
        elif path == "/__auth/access-rules":
            self._handle_list_access_rules(flow)
        elif path == "/__auth/request" and flow.request.method == "POST":
            self._handle_create_request(flow)
        elif path.startswith("/__auth/request/") and path.endswith("/status"):
            self._handle_poll_status(flow)
        else:
            _respond_json(flow, 404, {"error": "Not found"})

        return True

    def _handle_list_access_rules(self, flow: http.HTTPFlow) -> None:
        if self._access_store is None:
            _respond_json(flow, 200, [])
            return

        rules = self._access_store.rules
        domain_filter = flow.request.query.get("domain")

        result = []
        for rule in rules:
            if domain_filter and domain_filter.lower() not in rule.domain.lower():
                continue
            result.append({
                "domain": rule.domain,
                "mode": rule.mode,
                "paths": rule.paths,
            })

        _respond_json(flow, 200, result)

    async def _handle_list_credentials(self, flow: http.HTTPFlow) -> None:
        rules = await self._store.list()
        domain_filter = flow.request.query.get("domain")

        result = []
        for rule in rules:
            if domain_filter and domain_filter.lower() not in rule.domain.lower():
                continue
            result.append(
                {
                    "id": rule.id,
                    "domain": rule.domain,
                    "enabled": rule.enabled,
                }
            )

        _respond_json(flow, 200, result)

    def _handle_create_request(self, flow: http.HTTPFlow) -> None:
        # Rate limiting
        if not self._pending.check_rate_limit():
            _respond_json(flow, 429, {"error": "Rate limit exceeded"})
            return

        try:
            body = json.loads(flow.request.get_text() or "")
        except (json.JSONDecodeError, ValueError):
            _respond_json(flow, 400, {"error": "Invalid JSON"})
            return

        domain = body.get("domain", "")
        auth_type = body.get("auth_type")
        reason = body.get("reason", "")

        # Validate domain
        if not domain or not DOMAIN_RE.match(domain):
            _respond_json(flow, 400, {"error": "Invalid domain"})
            return

        # Validate reason length
        if len(reason) > 500:
            _respond_json(flow, 400, {"error": "Reason must be 500 characters or less"})
            return

        # Validate auth_type if provided
        if auth_type is not None and auth_type not in VALID_AUTH_TYPES:
            valid = ", ".join(sorted(VALID_AUTH_TYPES))
            _respond_json(flow, 400, {"error": f"Invalid auth_type. Must be one of: {valid}"})
            return

        req = self._pending.create(domain=domain, reason=reason, auth_type=auth_type)

        setup_url = f"http://localhost:{self._mgmt_port}/setup/{req.token}"
        logger.info("Credential request created: token=%s domain=%s", req.token[:8] + "...", domain)

        _respond_json(
            flow,
            200,
            {
                "setup_url": setup_url,
                "token": req.token,
                "expires_in": req.ttl,
            },
        )

    def _handle_poll_status(self, flow: http.HTTPFlow) -> None:
        # Extract token from /__auth/request/{token}/status
        parts = flow.request.path.split("/")
        if len(parts) < 5:
            _respond_json(flow, 404, {"error": "Not found"})
            return
        token = parts[3]

        status = self._pending.get_status(token)
        if status is None:
            _respond_json(flow, 404, {"error": "Unknown request token"})
            return

        _respond_json(flow, 200, {"status": status.value})


def _respond_json(flow: http.HTTPFlow, status: int, data: object) -> None:
    """Set a synthetic JSON response on the flow."""
    body = json.dumps(data)
    flow.response = http.Response.make(
        status,
        body.encode(),
        {"Content-Type": "application/json"},
    )
