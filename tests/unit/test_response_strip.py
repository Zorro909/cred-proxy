"""AC-4: Response stripping tests."""

from mitmproxy import http

from auth_injection_proxy.stripping.response_strip import strip_secrets
from tests.conftest import make_flow


class TestResponseStripping:
    def test_strips_bearer_from_body(self):
        """AC-4.1: Secret in response body is redacted."""
        flow = make_flow("https://api.openai.com/v1/echo")
        flow.response = http.Response.make(200, b'{"auth": "sk-secret"}')
        strip_secrets(flow, ["sk-secret"])
        assert b"sk-secret" not in flow.response.content
        assert b"[REDACTED]" in flow.response.content

    def test_strips_header_value(self):
        """AC-4.2: Secret in response headers is redacted."""
        flow = make_flow("https://api.example.com/echo")
        flow.response = http.Response.make(200, b"ok", {"X-Echo": "mysecret"})
        strip_secrets(flow, ["mysecret"])
        assert flow.response.headers["X-Echo"] == "[REDACTED]"

    def test_strips_query_param_value(self):
        """AC-4.3: Query param value in body is redacted."""
        flow = make_flow("https://legacy.example.com/api")
        flow.response = http.Response.make(200, b"key=secret123&other=data")
        strip_secrets(flow, ["secret123"])
        body = flow.response.get_text()
        assert "secret123" not in body
        assert "[REDACTED]" in body

    def test_preserves_unrelated_response(self):
        """AC-4.4: Response without secrets is unchanged."""
        flow = make_flow("https://api.example.com/data")
        original_body = b'{"data": "hello world"}'
        flow.response = http.Response.make(200, original_body)
        strip_secrets(flow, ["sk-secret-not-in-body"])
        assert flow.response.content == original_body

    def test_no_response(self):
        """No crash when response is None."""
        flow = make_flow("https://api.example.com/data")
        flow.response = None
        strip_secrets(flow, ["secret"])  # Should not raise

    def test_empty_secrets_list(self):
        """No crash with empty secrets list."""
        flow = make_flow("https://api.example.com/data")
        flow.response = http.Response.make(200, b"body")
        strip_secrets(flow, [])  # Should not raise
