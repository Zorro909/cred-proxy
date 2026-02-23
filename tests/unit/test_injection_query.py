"""AC-3.7–3.10: Query parameter injection tests."""

from auth_injection_proxy.injection.query_param import inject_query_param
from tests.conftest import make_flow


class TestQueryParamInjection:
    def test_injects_query_param(self):
        """AC-3.7: Query param added to URL."""
        flow = make_flow("https://legacy.example.com/api")
        secrets = inject_query_param(flow, "api_key", "key123")
        assert flow.request.query["api_key"] == "key123"
        assert "key123" in secrets

    def test_appends_to_existing(self):
        """AC-3.8: Appends to existing query params."""
        flow = make_flow("https://legacy.example.com/api?page=1")
        inject_query_param(flow, "api_key", "key123")
        assert flow.request.query["page"] == "1"
        assert flow.request.query["api_key"] == "key123"

    def test_url_encoded(self):
        """AC-3.9: Special chars are properly handled."""
        flow = make_flow("https://legacy.example.com/api")
        inject_query_param(flow, "api_key", "key with spaces&stuff")
        assert flow.request.query["api_key"] == "key with spaces&stuff"

    def test_replaces_same_name(self):
        """AC-3.10: Replaces existing param with same name."""
        flow = make_flow("https://legacy.example.com/api?api_key=wrong")
        inject_query_param(flow, "api_key", "correct")
        assert flow.request.query["api_key"] == "correct"
