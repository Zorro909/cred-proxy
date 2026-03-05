"""AC-1.1, AC-2, AC-3: Full proxy request cycle integration tests."""

from mitmproxy import http

from auth_injection_proxy.injection.external_script import ExternalScriptManager
from auth_injection_proxy.injection.injector import inject_auth
from auth_injection_proxy.injection.oauth2 import OAuth2TokenManager
from auth_injection_proxy.matching.models import (
    BasicAuth,
    BearerAuth,
    CredentialRule,
    HeaderAuth,
    QueryParamAuth,
)
from auth_injection_proxy.matching.rules import RuleMatcher
from auth_injection_proxy.stripping.response_strip import strip_secrets
from tests.conftest import make_flow


class TestFullRequestCycle:
    async def test_bearer_injection_and_strip(self):
        """Full cycle: match → inject bearer → strip from response."""
        rules = [
            CredentialRule(
                id="openai",
                domain="api.openai.com",
                path_prefix="/v1/",
                auth=BearerAuth(type="bearer", token="sk-secret-123"),
            )
        ]
        matcher = RuleMatcher(rules)
        oauth2 = OAuth2TokenManager()

        flow = make_flow("https://api.openai.com/v1/chat")
        rule = matcher.match("api.openai.com", "/v1/chat")
        assert rule is not None

        secrets = await inject_auth(flow, rule, oauth2, ExternalScriptManager(), ".")
        assert flow.request.headers["Authorization"] == "Bearer sk-secret-123"

        # Simulate upstream echoing the secret
        flow.response = http.Response.make(200, b'{"echo": "sk-secret-123"}')
        strip_secrets(flow, secrets)
        assert b"sk-secret-123" not in flow.response.content

    async def test_no_match_passthrough(self):
        """Unmatched request is untouched."""
        rules = [
            CredentialRule(
                id="openai",
                domain="api.openai.com",
                auth=BearerAuth(type="bearer", token="sk-123"),
            )
        ]
        matcher = RuleMatcher(rules)

        flow = make_flow("https://httpbin.org/get")
        rule = matcher.match("httpbin.org", "/get")
        assert rule is None
        assert "Authorization" not in flow.request.headers

    async def test_basic_auth_cycle(self):
        rules = [
            CredentialRule(
                id="jira",
                domain="jira.example.com",
                auth=BasicAuth(type="basic", username="user", password="pass"),
            )
        ]
        matcher = RuleMatcher(rules)
        oauth2 = OAuth2TokenManager()

        flow = make_flow("https://jira.example.com/api/issues")
        rule = matcher.match("jira.example.com", "/api/issues")
        assert rule is not None

        secrets = await inject_auth(flow, rule, oauth2, ExternalScriptManager(), ".")
        assert "Basic" in flow.request.headers["Authorization"]
        assert len(secrets) > 0

    async def test_header_auth_cycle(self):
        rules = [
            CredentialRule(
                id="custom",
                domain="api.example.com",
                auth=HeaderAuth(type="header", header_name="X-API-Key", header_value="key123"),
            )
        ]
        matcher = RuleMatcher(rules)
        oauth2 = OAuth2TokenManager()

        flow = make_flow("https://api.example.com/data")
        rule = matcher.match("api.example.com", "/data")
        secrets = await inject_auth(flow, rule, oauth2, ExternalScriptManager(), ".")
        assert flow.request.headers["X-API-Key"] == "key123"

        flow.response = http.Response.make(200, b"echoed key123 back")
        strip_secrets(flow, secrets)
        assert b"key123" not in flow.response.content

    async def test_query_param_cycle(self):
        rules = [
            CredentialRule(
                id="legacy",
                domain="legacy.example.com",
                auth=QueryParamAuth(type="query_param", param_name="api_key", param_value="secret"),
            )
        ]
        matcher = RuleMatcher(rules)
        oauth2 = OAuth2TokenManager()

        flow = make_flow("https://legacy.example.com/api?page=1")
        rule = matcher.match("legacy.example.com", "/api")
        secrets = await inject_auth(flow, rule, oauth2, ExternalScriptManager(), ".")
        assert flow.request.query["api_key"] == "secret"
        assert flow.request.query["page"] == "1"

        flow.response = http.Response.make(200, b"your key was secret")
        strip_secrets(flow, secrets)
        assert b"secret" not in flow.response.content

    async def test_disabled_rule_not_injected(self):
        rules = [
            CredentialRule(
                id="disabled",
                domain="api.openai.com",
                enabled=False,
                auth=BearerAuth(type="bearer", token="sk-123"),
            )
        ]
        matcher = RuleMatcher(rules)

        rule = matcher.match("api.openai.com", "/v1/chat")
        assert rule is None
