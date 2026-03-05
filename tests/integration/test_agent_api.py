"""AC-9, AC-10: Agent-facing endpoint integration tests."""

import json

import pytest

from auth_injection_proxy.access.store import AccessRuleStore
from auth_injection_proxy.agent_api.handlers import AgentApiHandler
from auth_injection_proxy.matching.models import BearerAuth, CredentialRule, HeaderAuth
from auth_injection_proxy.requests.pending import PendingRequestStore
from tests.conftest import MockCredentialStore, make_flow


@pytest.fixture
def handler():
    store = MockCredentialStore(
        [
            CredentialRule(
                id="openai",
                domain="api.openai.com",
                enabled=True,
                auth=BearerAuth(type="bearer", token="sk-secret"),
            ),
            CredentialRule(
                id="github",
                domain="api.github.com",
                enabled=True,
                auth=HeaderAuth(type="header", header_name="X-Key", header_value="ghp-secret"),
            ),
            CredentialRule(
                id="disabled",
                domain="disabled.com",
                enabled=False,
                auth=BearerAuth(type="bearer", token="t"),
            ),
        ]
    )
    pending = PendingRequestStore(default_ttl=900)
    return AgentApiHandler(store=store, pending=pending, mgmt_port=8081)


class TestCredentialDiscovery:
    async def test_list_all(self, handler):
        """AC-9.1: Lists all rules with only id, domain, enabled."""
        flow = make_flow("http://proxy/__auth/credentials")
        flow.request.path = "/__auth/credentials"
        await handler.handle(flow)

        data = json.loads(flow.response.get_text())
        assert len(data) == 3
        for item in data:
            assert set(item.keys()) == {"id", "domain", "enabled"}

    async def test_empty_store(self):
        """AC-9.2: Empty store returns []."""
        store = MockCredentialStore()
        pending = PendingRequestStore()
        h = AgentApiHandler(store=store, pending=pending)
        flow = make_flow("http://proxy/__auth/credentials")
        flow.request.path = "/__auth/credentials"
        await h.handle(flow)
        assert json.loads(flow.response.get_text()) == []

    async def test_filter_by_domain(self, handler):
        """AC-9.3: Filter by domain substring."""
        flow = make_flow("http://proxy/__auth/credentials?domain=github")
        flow.request.path = "/__auth/credentials"
        flow.request.query["domain"] = "github"
        await handler.handle(flow)
        data = json.loads(flow.response.get_text())
        assert len(data) == 1
        assert data[0]["id"] == "github"

    async def test_filter_no_match(self, handler):
        """AC-9.4: Filter with no match returns []."""
        flow = make_flow("http://proxy/__auth/credentials?domain=stripe")
        flow.request.path = "/__auth/credentials"
        flow.request.query["domain"] = "stripe"
        await handler.handle(flow)
        assert json.loads(flow.response.get_text()) == []

    async def test_no_secret_leakage(self, handler):
        """AC-9.5: No auth secrets in response."""
        flow = make_flow("http://proxy/__auth/credentials")
        flow.request.path = "/__auth/credentials"
        await handler.handle(flow)
        body = flow.response.get_text()
        assert "sk-secret" not in body
        assert "ghp-secret" not in body


class TestCredentialRequests:
    async def test_create_with_auth_type(self, handler):
        """AC-10.1: Create returns setup_url, token, expires_in."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "api.example.com",
                    "auth_type": "bearer",
                    "reason": "Need API access",
                }
            )
        )
        await handler.handle(flow)
        data = json.loads(flow.response.get_text())
        assert "setup_url" in data
        assert "token" in data
        assert data["expires_in"] == 900

    async def test_create_without_auth_type(self, handler):
        """AC-10.2: Create without auth_type succeeds."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "api.example.com",
                    "reason": "test",
                }
            )
        )
        await handler.handle(flow)
        assert flow.response.status_code == 200

    async def test_invalid_auth_type(self, handler):
        """AC-10.3: Invalid auth_type → 400."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "api.example.com",
                    "auth_type": "kerberos",
                }
            )
        )
        await handler.handle(flow)
        assert flow.response.status_code == 400

    async def test_invalid_domain(self, handler):
        """AC-10.4: Invalid domain → 400."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "not a domain!!!",
                    "reason": "test",
                }
            )
        )
        await handler.handle(flow)
        assert flow.response.status_code == 400

    async def test_reason_too_long(self, handler):
        """AC-10.5: Reason > 500 chars → 400."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "api.example.com",
                    "reason": "x" * 501,
                }
            )
        )
        await handler.handle(flow)
        assert flow.response.status_code == 400


class TestWebhookUrl:
    async def test_create_with_webhook_url(self, handler):
        """Webhook URL is accepted and stored."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "api.example.com",
                    "reason": "test",
                    "webhook_url": "https://hooks.example.com/whk_123",
                }
            )
        )
        await handler.handle(flow)
        assert flow.response.status_code == 200
        data = json.loads(flow.response.get_text())
        assert "token" in data

    async def test_create_without_webhook_url(self, handler):
        """Request without webhook_url still works."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(json.dumps({"domain": "api.example.com", "reason": "test"}))
        await handler.handle(flow)
        assert flow.response.status_code == 200

    async def test_invalid_webhook_url_ftp(self, handler):
        """FTP webhook URL is rejected."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "api.example.com",
                    "reason": "test",
                    "webhook_url": "ftp://example.com/hook",
                }
            )
        )
        await handler.handle(flow)
        assert flow.response.status_code == 400
        data = json.loads(flow.response.get_text())
        assert "webhook_url" in data["error"]

    async def test_invalid_webhook_url_not_string(self, handler):
        """Non-string webhook URL is rejected."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "api.example.com",
                    "reason": "test",
                    "webhook_url": 12345,
                }
            )
        )
        await handler.handle(flow)
        assert flow.response.status_code == 400

    async def test_invalid_webhook_url_empty(self, handler):
        """Empty string webhook URL is rejected."""
        flow = make_flow("http://proxy/__auth/request")
        flow.request.method = "POST"
        flow.request.path = "/__auth/request"
        flow.request.set_text(
            json.dumps(
                {
                    "domain": "api.example.com",
                    "reason": "test",
                    "webhook_url": "",
                }
            )
        )
        await handler.handle(flow)
        assert flow.response.status_code == 400


class TestStatusPolling:
    async def test_poll_pending(self, handler):
        """AC-12.1: Pending status."""
        # Create a request first
        flow1 = make_flow("http://proxy/__auth/request")
        flow1.request.method = "POST"
        flow1.request.path = "/__auth/request"
        flow1.request.set_text(json.dumps({"domain": "api.example.com", "reason": "t"}))
        await handler.handle(flow1)
        token = json.loads(flow1.response.get_text())["token"]

        # Poll status
        flow2 = make_flow(f"http://proxy/__auth/request/{token}/status")
        flow2.request.path = f"/__auth/request/{token}/status"
        await handler.handle(flow2)
        data = json.loads(flow2.response.get_text())
        assert data["status"] == "pending"

    async def test_poll_unknown(self, handler):
        """AC-12.4: Unknown token → 404."""
        flow = make_flow("http://proxy/__auth/request/fakefake/status")
        flow.request.path = "/__auth/request/fakefake/status"
        await handler.handle(flow)
        assert flow.response.status_code == 404


class TestAccessRulesAgent:
    @pytest.fixture
    def handler_with_access(self, tmp_path):
        main = tmp_path / "access-rules.yaml"
        main.write_text("""access_rules:
  - id: gh-allow
    domain: api.github.com
    mode: allow
    paths:
      - "^/repos/"
      - "^/user$"
  - id: oai-deny
    domain: api.openai.com
    mode: deny
    paths:
      - "^/v1/files"
""")
        access_store = AccessRuleStore(tmp_path)
        store = MockCredentialStore()
        pending = PendingRequestStore()
        return AgentApiHandler(
            store=store, pending=pending, mgmt_port=8081,
            access_store=access_store,
        )

    async def test_list_access_rules_agent(self, handler_with_access):
        """AC-10.59: /__auth/access-rules returns flat list (no IDs or groups)."""
        flow = make_flow("http://proxy/__auth/access-rules")
        flow.request.path = "/__auth/access-rules"
        await handler_with_access.handle(flow)

        data = json.loads(flow.response.get_text())
        assert len(data) == 2
        for item in data:
            assert set(item.keys()) == {"domain", "mode", "paths"}
            assert "id" not in item

    async def test_list_access_rules_domain_filter(self, handler_with_access):
        """AC-10.60: /__auth/access-rules?domain=github filters correctly."""
        flow = make_flow("http://proxy/__auth/access-rules?domain=github")
        flow.request.path = "/__auth/access-rules"
        flow.request.query["domain"] = "github"
        await handler_with_access.handle(flow)

        data = json.loads(flow.response.get_text())
        assert len(data) == 1
        assert data[0]["domain"] == "api.github.com"
