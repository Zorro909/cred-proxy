"""AC-10.12 to AC-10.22: Unit tests for AccessRuleMatcher."""

from auth_injection_proxy.access.matcher import AccessRuleMatcher
from auth_injection_proxy.access.models import AccessRule


def _rule(
    id: str = "r1",
    domain: str = "api.github.com",
    mode: str = "allow",
    paths: list[str] | None = None,
) -> AccessRule:
    return AccessRule(id=id, domain=domain, mode=mode, paths=paths or ["^/repos/"])


class TestAccessRuleMatcher:
    def test_no_rules_allows_all(self):
        """AC-10.12: Empty matcher allows everything."""
        m = AccessRuleMatcher()
        assert m.is_allowed("api.github.com", "/repos/foo") is True
        assert m.is_allowed("any.host.com", "/anything") is True

    def test_exact_domain_match(self):
        """AC-10.13: Rule for api.github.com matches that host."""
        m = AccessRuleMatcher([_rule(domain="api.github.com")])
        assert m.is_allowed("api.github.com", "/repos/foo") is True
        assert m.is_allowed("api.github.com", "/gists") is False

    def test_exact_domain_no_match(self):
        """AC-10.14: Rule for api.github.com does not match other.github.com."""
        m = AccessRuleMatcher([_rule(domain="api.github.com")])
        # other.github.com has no rule, so it's allowed
        assert m.is_allowed("other.github.com", "/anything") is True

    def test_wildcard_domain_match(self):
        """AC-10.15: Rule for *.github.com matches api.github.com."""
        m = AccessRuleMatcher([_rule(domain="*.github.com")])
        assert m.is_allowed("api.github.com", "/repos/foo") is True
        assert m.is_allowed("api.github.com", "/gists") is False

    def test_wildcard_bare_domain_no_match(self):
        """AC-10.16: Rule for *.github.com does not match github.com."""
        m = AccessRuleMatcher([_rule(domain="*.github.com")])
        # github.com has no matching rule, so it's allowed
        assert m.is_allowed("github.com", "/anything") is True

    def test_case_insensitive_domain(self):
        """AC-10.17: API.GitHub.com matches rule for api.github.com."""
        m = AccessRuleMatcher([_rule(domain="api.github.com")])
        assert m.is_allowed("API.GitHub.com", "/repos/foo") is True
        assert m.is_allowed("API.GitHub.com", "/gists") is False

    def test_first_match_wins(self):
        """AC-10.18: Two rules for overlapping domains; first one applies."""
        rules = [
            AccessRule(
                id="specific", domain="api.github.com", mode="deny",
                paths=["^/admin"],
            ),
            AccessRule(
                id="wildcard", domain="*.github.com", mode="allow",
                paths=["^/repos/"],
            ),
        ]
        m = AccessRuleMatcher(rules)
        # api.github.com matches the first rule (deny), /admin is blocked
        assert m.is_allowed("api.github.com", "/admin") is False
        # api.github.com matches the first rule (deny), /repos/foo is allowed
        assert m.is_allowed("api.github.com", "/repos/foo") is True

    def test_update_rules(self):
        """AC-10.19: update_rules() replaces the rule set."""
        m = AccessRuleMatcher([_rule(domain="api.github.com")])
        assert m.is_allowed("api.github.com", "/gists") is False

        m.update_rules([_rule(domain="other.com")])
        # api.github.com now has no rule
        assert m.is_allowed("api.github.com", "/gists") is True

    def test_no_matching_domain_allows(self):
        """AC-10.20: Request to a domain with no rule is allowed."""
        m = AccessRuleMatcher([_rule(domain="api.github.com")])
        assert m.is_allowed("httpbin.org", "/anything") is True

    def test_get_rule_for_host_found(self):
        """AC-10.21: get_rule_for_host returns the matching rule."""
        rule = _rule(domain="api.github.com")
        m = AccessRuleMatcher([rule])
        result = m.get_rule_for_host("api.github.com")
        assert result is not None
        assert result.id == rule.id

    def test_get_rule_for_host_none(self):
        """AC-10.22: get_rule_for_host returns None for unmatched domain."""
        m = AccessRuleMatcher([_rule(domain="api.github.com")])
        assert m.get_rule_for_host("other.com") is None
