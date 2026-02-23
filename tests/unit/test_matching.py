"""AC-2: Rule matching tests."""

from auth_injection_proxy.matching.models import BearerAuth, CredentialRule
from auth_injection_proxy.matching.rules import RuleMatcher


def _rule(
    domain: str,
    rule_id: str = "r1",
    path_prefix: str | None = None,
    enabled: bool = True,
    token: str = "tok",
) -> CredentialRule:
    return CredentialRule(
        id=rule_id,
        domain=domain,
        path_prefix=path_prefix,
        enabled=enabled,
        auth=BearerAuth(type="bearer", token=token),
    )


class TestDomainMatching:
    def test_exact_match(self):
        """AC-2.1: Exact domain matches."""
        m = RuleMatcher([_rule("api.openai.com")])
        assert m.match("api.openai.com", "/v1/chat") is not None

    def test_exact_non_match(self):
        """AC-2.2: Different subdomain doesn't match."""
        m = RuleMatcher([_rule("api.openai.com")])
        assert m.match("other.openai.com", "/v1/chat") is None

    def test_wildcard_match(self):
        """AC-2.3: *.github.com matches api.github.com."""
        m = RuleMatcher([_rule("*.github.com")])
        assert m.match("api.github.com", "/repos") is not None

    def test_wildcard_bare_domain_no_match(self):
        """AC-2.4: *.github.com does NOT match github.com."""
        m = RuleMatcher([_rule("*.github.com")])
        assert m.match("github.com", "/repos") is None

    def test_wildcard_deep_subdomain(self):
        """AC-2.5: *.github.com matches raw.objects.github.com."""
        m = RuleMatcher([_rule("*.github.com")])
        assert m.match("raw.objects.github.com", "/file") is not None

    def test_case_insensitive(self):
        """AC-2.13: Domain matching is case-insensitive."""
        m = RuleMatcher([_rule("api.openai.com")])
        assert m.match("API.OpenAI.com", "/v1/chat") is not None


class TestPathMatching:
    def test_path_prefix_match(self):
        """AC-2.6: Path prefix matches."""
        m = RuleMatcher([_rule("api.example.com", path_prefix="/v1/")])
        assert m.match("api.example.com", "/v1/users") is not None

    def test_path_prefix_non_match(self):
        """AC-2.7: Wrong path prefix doesn't match."""
        m = RuleMatcher([_rule("api.example.com", path_prefix="/v1/")])
        assert m.match("api.example.com", "/v2/users") is None

    def test_no_path_matches_all(self):
        """AC-2.8: No path prefix matches everything."""
        m = RuleMatcher([_rule("api.example.com")])
        assert m.match("api.example.com", "/anything/here") is not None


class TestOrdering:
    def test_first_match_wins(self):
        """AC-2.9: First matching rule wins."""
        r1 = _rule("api.example.com", rule_id="r1", path_prefix="/v1/", token="A")
        r2 = _rule("api.example.com", rule_id="r2", token="B")
        m = RuleMatcher([r1, r2])
        result = m.match("api.example.com", "/v1/data")
        assert result is not None
        assert result.id == "r1"

    def test_second_rule_when_first_doesnt_match(self):
        """AC-2.10: Falls through to second rule."""
        r1 = _rule("api.example.com", rule_id="r1", path_prefix="/v1/", token="A")
        r2 = _rule("api.example.com", rule_id="r2", token="B")
        m = RuleMatcher([r1, r2])
        result = m.match("api.example.com", "/v2/data")
        assert result is not None
        assert result.id == "r2"

    def test_no_match_passthrough(self):
        """AC-2.11: No match returns None."""
        m = RuleMatcher([_rule("api.openai.com")])
        assert m.match("httpbin.org", "/get") is None

    def test_disabled_rule_skipped(self):
        """AC-2.12: Disabled rules are skipped."""
        m = RuleMatcher([_rule("api.openai.com", enabled=False)])
        assert m.match("api.openai.com", "/v1/chat") is None


class TestUpdateRules:
    def test_update_rules(self):
        m = RuleMatcher()
        assert m.match("api.openai.com", "/") is None
        m.update_rules([_rule("api.openai.com")])
        assert m.match("api.openai.com", "/") is not None
