"""Rule matching engine — domain, path, ordering."""

from __future__ import annotations

from auth_injection_proxy.matching.models import CredentialRule


class RuleMatcher:
    def __init__(self, rules: list[CredentialRule] | None = None) -> None:
        self._rules: list[CredentialRule] = rules or []

    def update_rules(self, rules: list[CredentialRule]) -> None:
        self._rules = rules

    def match(self, host: str, path: str) -> CredentialRule | None:
        """Find the first matching enabled rule for a given host and path.

        Domain matching is case-insensitive. Wildcard patterns like *.domain.com
        match any subdomain but not the bare domain.
        """
        host_lower = host.lower()
        for rule in self._rules:
            if not rule.enabled:
                continue
            if not self._domain_matches(rule.domain.lower(), host_lower):
                continue
            if rule.path_prefix and not path.startswith(rule.path_prefix):
                continue
            return rule
        return None

    @staticmethod
    def _domain_matches(pattern: str, host: str) -> bool:
        if pattern.startswith("*."):
            # Wildcard: *.github.com matches api.github.com, raw.objects.github.com
            # but NOT github.com itself
            suffix = pattern[1:]  # ".github.com"
            return host.endswith(suffix) and host != suffix.lstrip(".")
        return pattern == host
