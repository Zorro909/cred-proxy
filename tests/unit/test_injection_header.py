"""AC-3.5–3.6: Custom header injection tests."""

from auth_injection_proxy.injection.header import inject_header
from tests.conftest import make_flow


class TestHeaderInjection:
    def test_injects_custom_header(self):
        """AC-3.5: Custom header is set, no Authorization added."""
        flow = make_flow("https://api.example.com/data")
        secrets = inject_header(flow, "X-API-Key", "key123")
        assert flow.request.headers["X-API-Key"] == "key123"
        assert "Authorization" not in flow.request.headers
        assert "key123" in secrets

    def test_preserves_unrelated_headers(self):
        """AC-3.6: Existing unrelated headers are preserved."""
        flow = make_flow("https://api.example.com/data")
        flow.request.headers["X-Request-Id"] = "req-abc"
        inject_header(flow, "X-API-Key", "key123")
        assert flow.request.headers["X-Request-Id"] == "req-abc"
        assert flow.request.headers["X-API-Key"] == "key123"
