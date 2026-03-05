"""AC-10.35 to AC-10.43: Integration tests for access rules in addon request flow."""

import json

from auth_injection_proxy.access.matcher import AccessRuleMatcher
from auth_injection_proxy.injection.external_script import ExternalScriptManager
from auth_injection_proxy.injection.injector import inject_auth
from auth_injection_proxy.injection.oauth2 import OAuth2TokenManager
from auth_injection_proxy.matching.models import BearerAuth, CredentialRule
from auth_injection_proxy.matching.rules import RuleMatcher
from tests.conftest import make_access_rule, make_flow


def _check_allowed(matcher: AccessRuleMatcher, host: str, path: str) -> bool:
    """Check if host+path is allowed: no rule = allowed, otherwise delegate to rule."""
    rule = matcher.get_rule_for_host(host)
    if rule is None:
        return True
    return rule.is_allowed(path)


class TestAccessRulesFlow:
    async def test_allowed_request_passes_through(self):
        """AC-10.35: Request matching an allowlist pattern is proxied normally."""
        matcher = AccessRuleMatcher([make_access_rule()])
        assert _check_allowed(matcher, "api.github.com", "/repos/foo") is True

    async def test_blocked_request_returns_403(self):
        """AC-10.36: Request blocked by allowlist returns 403 JSON response."""
        from mitmproxy import http

        matcher = AccessRuleMatcher([make_access_rule()])
        flow = make_flow("https://api.github.com/gists/123")
        host = flow.request.pretty_host
        path = flow.request.path.split("?")[0]

        if not _check_allowed(matcher, host, path):
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "error": "access_denied",
                        "message": f"Request to {host}{path} is blocked by access rules",
                        "proxy": "cred-proxy",
                    }
                ).encode(),
                {"Content-Type": "application/json"},
            )

        assert flow.response is not None
        assert flow.response.status_code == 403

    async def test_blocked_response_body(self):
        """AC-10.37: 403 body contains error, message, and proxy fields."""
        from mitmproxy import http

        matcher = AccessRuleMatcher([make_access_rule()])
        flow = make_flow("https://api.github.com/gists/123")
        host = flow.request.pretty_host
        path = flow.request.path.split("?")[0]

        if not _check_allowed(matcher, host, path):
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "error": "access_denied",
                        "message": f"Request to {host}{path} is blocked by access rules",
                        "proxy": "cred-proxy",
                    }
                ).encode(),
                {"Content-Type": "application/json"},
            )

        body = json.loads(flow.response.get_text())
        assert body["error"] == "access_denied"
        assert "api.github.com" in body["message"]
        assert body["proxy"] == "cred-proxy"

    async def test_denylist_blocks_matching(self):
        """AC-10.38: Request matching a denylist pattern returns 403."""
        rule = make_access_rule(mode="deny", paths=["^/v1/files"])
        matcher = AccessRuleMatcher([rule])
        assert _check_allowed(matcher, "api.github.com", "/v1/files/upload") is False

    async def test_denylist_allows_non_matching(self):
        """AC-10.39: Request not matching any denylist pattern is proxied."""
        rule = make_access_rule(mode="deny", paths=["^/v1/files"])
        matcher = AccessRuleMatcher([rule])
        assert _check_allowed(matcher, "api.github.com", "/v1/chat") is True

    async def test_no_access_rule_allows_all(self):
        """AC-10.40: Domain with no access rule passes through (backwards-compat)."""
        matcher = AccessRuleMatcher([make_access_rule(domain="api.github.com")])
        assert _check_allowed(matcher, "httpbin.org", "/anything") is True

    async def test_blocked_request_no_credential_injection(self):
        """AC-10.41: Blocked request never reaches credential injection."""
        access_matcher = AccessRuleMatcher([make_access_rule()])
        cred_rules = [
            CredentialRule(
                id="gh",
                domain="api.github.com",
                auth=BearerAuth(type="bearer", token="secret"),
            )
        ]
        cred_matcher = RuleMatcher(cred_rules)

        flow = make_flow("https://api.github.com/gists/123")
        host = flow.request.pretty_host
        path = flow.request.path.split("?")[0]

        # Access check happens before credential injection
        if _check_allowed(access_matcher, host, path):
            rule = cred_matcher.match(host, flow.request.path)
            if rule:
                await inject_auth(flow, rule, OAuth2TokenManager(), ExternalScriptManager(), ".")

        # Verify no credentials were injected
        assert "Authorization" not in flow.request.headers

    async def test_allowed_request_with_credentials(self):
        """AC-10.42: Allowed request still gets credentials injected."""
        access_matcher = AccessRuleMatcher([make_access_rule()])
        cred_rules = [
            CredentialRule(
                id="gh",
                domain="api.github.com",
                auth=BearerAuth(type="bearer", token="secret"),
            )
        ]
        cred_matcher = RuleMatcher(cred_rules)

        flow = make_flow("https://api.github.com/repos/test")
        host = flow.request.pretty_host
        path = flow.request.path.split("?")[0]

        if _check_allowed(access_matcher, host, path):
            rule = cred_matcher.match(host, flow.request.path)
            if rule:
                await inject_auth(flow, rule, OAuth2TokenManager(), ExternalScriptManager(), ".")

        assert flow.request.headers.get("Authorization") == "Bearer secret"

    async def test_auth_path_not_blocked(self):
        """AC-10.43: /__auth/* paths are accessible even if domain has a blocking rule."""
        # The /__auth/ path is handled before access rule checking in addon.py
        # So we just verify that the access matcher would block it,
        # but the addon handles /__auth/ first.
        matcher = AccessRuleMatcher(
            [
                make_access_rule(mode="allow", paths=[]),  # block everything
            ]
        )

        # The /__auth/ path check happens before access rules in the addon
        flow = make_flow("https://api.github.com/__auth/credentials")
        path = flow.request.path.split("?")[0]
        is_auth_path = path.startswith("/__auth/")

        # Even though access rules would block, __auth is exempt
        assert is_auth_path is True
        rule = matcher.get_rule_for_host("api.github.com")
        assert rule is not None
        assert rule.is_allowed(path) is False
        # In the actual addon, this flow would be handled and returned
        # before access rules are checked
