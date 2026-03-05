"""Access rule matching engine."""

from __future__ import annotations

from auth_injection_proxy.access.models import AccessRule


class AccessRuleMatcher:
    def __init__(self, rules: list[AccessRule] | None = None) -> None:
        self._rules: list[AccessRule] = rules or []

    def update_rules(self, rules: list[AccessRule]) -> None:
        self._rules = rules

    def is_allowed(self, host: str, path: str) -> bool:
        """Check if a request to host+path is permitted.

        Returns True if allowed, False if blocked.
        If no access rule matches the domain, the request is allowed (default-open).
        """
        rule = self._find_rule(host)
        if rule is None:
            return True  # no access rule for this domain -> allow
        return rule.is_allowed(path)

    def get_rule_for_host(self, host: str) -> AccessRule | None:
        """Return the access rule matching this host, or None."""
        return self._find_rule(host)

    def _find_rule(self, host: str) -> AccessRule | None:
        """Find the access rule for a host using the same domain matching
        logic as credential rules (exact match or wildcard)."""
        host_lower = host.lower()
        for rule in self._rules:
            if self._domain_matches(rule.domain.lower(), host_lower):
                return rule
        return None

    @staticmethod
    def _domain_matches(pattern: str, host: str) -> bool:
        """Same domain matching logic as CredentialRuleMatcher."""
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".github.com"
            return host.endswith(suffix) and host != suffix.lstrip(".")
        return pattern == host
