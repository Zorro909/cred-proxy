"""AC-10.1 to AC-10.11: Unit tests for AccessRule model."""

import re

import pytest
from pydantic import ValidationError

from auth_injection_proxy.access.models import AccessRule


class TestAccessRuleModel:
    def test_allowlist_matching_path(self):
        """AC-10.1: Allowlist mode allows a matching path."""
        rule = AccessRule(
            id="gh", domain="api.github.com", mode="allow",
            paths=["^/repos/", "^/user$"],
        )
        assert rule.is_allowed("/repos/octocat/hello") is True

    def test_allowlist_blocking_path(self):
        """AC-10.2: Allowlist mode blocks a non-matching path."""
        rule = AccessRule(
            id="gh", domain="api.github.com", mode="allow",
            paths=["^/repos/", "^/user$"],
        )
        assert rule.is_allowed("/gists/123") is False

    def test_denylist_matching_path(self):
        """AC-10.3: Denylist mode blocks a matching path."""
        rule = AccessRule(
            id="oai", domain="api.openai.com", mode="deny",
            paths=["^/v1/files", "^/v1/fine_tuning"],
        )
        assert rule.is_allowed("/v1/files/upload") is False

    def test_denylist_allowing_path(self):
        """AC-10.4: Denylist mode allows a non-matching path."""
        rule = AccessRule(
            id="oai", domain="api.openai.com", mode="deny",
            paths=["^/v1/files", "^/v1/fine_tuning"],
        )
        assert rule.is_allowed("/v1/chat/completions") is True

    def test_empty_allowlist_blocks_all(self):
        """AC-10.5: mode='allow' with paths=[] blocks everything."""
        rule = AccessRule(
            id="block", domain="example.com", mode="allow", paths=[],
        )
        assert rule.is_allowed("/anything") is False
        assert rule.is_allowed("/") is False

    def test_empty_denylist_allows_all(self):
        """AC-10.6: mode='deny' with paths=[] allows everything."""
        rule = AccessRule(
            id="allow", domain="example.com", mode="deny", paths=[],
        )
        assert rule.is_allowed("/anything") is True
        assert rule.is_allowed("/") is True

    def test_invalid_regex_rejected(self):
        """AC-10.7: Invalid regex in paths raises ValidationError."""
        with pytest.raises(ValidationError):
            AccessRule(
                id="bad", domain="example.com", mode="allow",
                paths=["^/valid", "[invalid"],
            )

    def test_regex_anchoring(self):
        """AC-10.8: ^/repos/ matches /repos/foo but not /v1/repos/foo."""
        rule = AccessRule(
            id="gh", domain="api.github.com", mode="allow",
            paths=["^/repos/"],
        )
        assert rule.path_matches("/repos/foo") is True
        assert rule.path_matches("/v1/repos/foo") is False

    def test_regex_no_anchor(self):
        """AC-10.9: /repos/ matches both /repos/foo and /v1/repos/foo (no ^)."""
        rule = AccessRule(
            id="gh", domain="api.github.com", mode="allow",
            paths=["/repos/"],
        )
        assert rule.path_matches("/repos/foo") is True
        assert rule.path_matches("/v1/repos/foo") is True

    def test_patterns_compiled_once(self):
        """AC-10.10: Verify _compiled is populated after construction."""
        rule = AccessRule(
            id="gh", domain="api.github.com", mode="allow",
            paths=["^/repos/", "^/user$"],
        )
        assert len(rule._compiled) == 2
        assert all(isinstance(p, re.Pattern) for p in rule._compiled)

    def test_serialization_roundtrip(self):
        """AC-10.11: model_dump() and model_validate() produce equivalent objects."""
        rule = AccessRule(
            id="gh", domain="api.github.com", mode="allow",
            paths=["^/repos/", "^/user$"],
        )
        dumped = rule.model_dump()
        restored = AccessRule.model_validate(dumped)
        assert restored.id == rule.id
        assert restored.domain == rule.domain
        assert restored.mode == rule.mode
        assert restored.paths == rule.paths
        assert restored.is_allowed("/repos/foo") == rule.is_allowed("/repos/foo")
