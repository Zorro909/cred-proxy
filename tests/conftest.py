"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from mitmproxy import http
from mitmproxy.test import tflow

from auth_injection_proxy.access.models import AccessRule
from auth_injection_proxy.matching.models import (
    BasicAuth,
    BearerAuth,
    CredentialRule,
    HeaderAuth,
    OAuth2ClientCredentialsAuth,
    QueryParamAuth,
)
from auth_injection_proxy.store.interface import CredentialStore


class MockCredentialStore(CredentialStore):
    """In-memory credential store for testing."""

    def __init__(self, rules: list[CredentialRule] | None = None) -> None:
        self._rules: list[CredentialRule] = list(rules) if rules else []

    async def list(self) -> list[CredentialRule]:
        return list(self._rules)

    async def get(self, rule_id: str) -> CredentialRule | None:
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None

    async def create(self, rule: CredentialRule) -> None:
        for r in self._rules:
            if r.id == rule.id:
                raise ValueError(f"Duplicate id: {rule.id}")
        self._rules.append(rule)

    async def update(self, rule_id: str, rule: CredentialRule) -> None:
        for i, r in enumerate(self._rules):
            if r.id == rule_id:
                self._rules[i] = rule
                return
        raise KeyError(rule_id)

    async def delete(self, rule_id: str) -> None:
        for i, r in enumerate(self._rules):
            if r.id == rule_id:
                self._rules.pop(i)
                return
        raise KeyError(rule_id)

    async def watch(self, callback: Callable[[list[CredentialRule]], None]) -> None:
        pass


@pytest.fixture
def bearer_rule() -> CredentialRule:
    return CredentialRule(
        id="test-bearer",
        domain="api.openai.com",
        path_prefix="/v1/",
        enabled=True,
        auth=BearerAuth(type="bearer", token="sk-test123"),
    )


@pytest.fixture
def basic_rule() -> CredentialRule:
    return CredentialRule(
        id="test-basic",
        domain="jira.example.com",
        enabled=True,
        auth=BasicAuth(type="basic", username="user@org", password="p@ss:word"),
    )


@pytest.fixture
def header_rule() -> CredentialRule:
    return CredentialRule(
        id="test-header",
        domain="api.example.com",
        enabled=True,
        auth=HeaderAuth(type="header", header_name="X-API-Key", header_value="key123"),
    )


@pytest.fixture
def query_rule() -> CredentialRule:
    return CredentialRule(
        id="test-query",
        domain="legacy.example.com",
        enabled=True,
        auth=QueryParamAuth(type="query_param", param_name="api_key", param_value="key123"),
    )


@pytest.fixture
def oauth2_rule() -> CredentialRule:
    return CredentialRule(
        id="test-oauth2",
        domain="api.service.com",
        enabled=True,
        auth=OAuth2ClientCredentialsAuth(
            type="oauth2_client_credentials",
            token_url="https://auth.service.com/oauth/token",
            client_id="my-client-id",
            client_secret="my-client-secret",
            scopes=["read", "write"],
        ),
    )


@pytest.fixture
def mock_store() -> MockCredentialStore:
    return MockCredentialStore()


@pytest.fixture
def sample_yaml(tmp_path: object) -> str:
    """Create a sample YAML config file and return its path."""
    import os

    path = os.path.join(str(tmp_path), "credentials.yaml")
    with open(path, "w") as f:
        f.write("""proxy:
  listen_port: 8080
  mgmt_port: 8081
  credential_request_ttl: 900

credentials:
  - id: "openai-prod"
    domain: "api.openai.com"
    path_prefix: "/v1/"
    enabled: true
    auth:
      type: bearer
      token: "sk-test-token-123"
  - id: "github-api"
    domain: "*.github.com"
    enabled: true
    auth:
      type: header
      header_name: "X-API-Key"
      header_value: "ghp-secret-token"
""")
    return path


def make_flow(
    url: str = "https://api.openai.com/v1/chat",
    method: str = "GET",
    content: bytes = b"",
) -> http.HTTPFlow:
    """Create a test HTTPFlow with the given URL."""
    flow = tflow.tflow()
    flow.request = http.Request.make(method, url, content)
    return flow


def make_access_rule(
    id: str = "r1",
    domain: str = "api.github.com",
    mode: str = "allow",
    paths: list[str] | None = None,
) -> AccessRule:
    """Create an AccessRule for testing."""
    return AccessRule(id=id, domain=domain, mode=mode, paths=paths or ["^/repos/"])
