"""AC-3.1–3.2: Bearer token injection tests."""

from auth_injection_proxy.injection.bearer import inject_bearer
from tests.conftest import make_flow


class TestBearerInjection:
    def test_injects_bearer_header(self):
        """AC-3.1: Bearer token sets Authorization header."""
        flow = make_flow("https://api.openai.com/v1/chat")
        secrets = inject_bearer(flow, "sk-test123")
        assert flow.request.headers["Authorization"] == "Bearer sk-test123"
        assert "sk-test123" in secrets

    def test_replaces_existing_auth(self):
        """AC-3.2: Replaces existing Authorization header."""
        flow = make_flow("https://api.openai.com/v1/chat")
        flow.request.headers["Authorization"] = "Bearer old-token"
        inject_bearer(flow, "sk-new")
        assert flow.request.headers["Authorization"] == "Bearer sk-new"
