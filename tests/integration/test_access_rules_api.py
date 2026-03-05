"""AC-10.44 to AC-10.58: Integration tests for access rules management API."""

import pytest
from fastapi.testclient import TestClient

from auth_injection_proxy.access.store import AccessRuleStore
from auth_injection_proxy.mgmt.app import create_app
from auth_injection_proxy.requests.pending import PendingRequestStore
from tests.conftest import MockCredentialStore


@pytest.fixture
def store_dir(tmp_path):
    """Create a config dir with some access rules."""
    main = tmp_path / "access-rules.yaml"
    main.write_text("""access_rules:
  - id: openai-denylist
    domain: api.openai.com
    mode: deny
    paths:
      - "^/v1/files"
      - "^/v1/fine_tuning"
""")
    d = tmp_path / "access-rules.d"
    d.mkdir()
    (d / "github.yaml").write_text("""access_rules:
  - id: github-allowlist
    domain: api.github.com
    mode: allow
    paths:
      - "^/repos/"
      - "^/user$"
""")
    return tmp_path


@pytest.fixture
def client(store_dir):
    access_store = AccessRuleStore(store_dir)
    cred_store = MockCredentialStore()
    pending = PendingRequestStore()
    app = create_app(cred_store, pending, access_store)
    return TestClient(app)


@pytest.fixture
def empty_client(tmp_path):
    access_store = AccessRuleStore(tmp_path)
    cred_store = MockCredentialStore()
    pending = PendingRequestStore()
    app = create_app(cred_store, pending, access_store)
    return TestClient(app)


class TestListAccessRules:
    def test_list_access_rules_grouped(self, client):
        """AC-10.44: GET /api/access-rules returns rules grouped by file."""
        resp = client.get("/api/access-rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "groups" in data
        assert "default" in data["groups"]
        assert "github" in data["groups"]
        assert len(data["groups"]["default"]) == 1
        assert len(data["groups"]["github"]) == 1
        assert data["groups"]["default"][0]["id"] == "openai-denylist"
        assert data["groups"]["github"][0]["id"] == "github-allowlist"


class TestGetAccessRule:
    def test_get_access_rule_with_group(self, client):
        """AC-10.45: GET /api/access-rules/{id} returns rule with group name."""
        resp = client.get("/api/access-rules/github-allowlist")
        assert resp.status_code == 200
        data = resp.json()
        assert data["group"] == "github"
        assert data["rule"]["id"] == "github-allowlist"
        assert data["rule"]["domain"] == "api.github.com"
        assert data["rule"]["mode"] == "allow"

    def test_get_nonexistent(self, client):
        """AC-10.46: GET /api/access-rules/{id} returns 404."""
        resp = client.get("/api/access-rules/nonexistent")
        assert resp.status_code == 404


class TestCreateAccessRule:
    def test_create_in_default_group(self, empty_client):
        """AC-10.47: POST without group creates in default (access-rules.yaml)."""
        resp = empty_client.post(
            "/api/access-rules",
            json={
                "id": "new-rule",
                "domain": "example.com",
                "mode": "allow",
                "paths": ["^/api/"],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["id"] == "new-rule"

        # Verify it's in the default group
        listed = empty_client.get("/api/access-rules").json()
        assert "default" in listed["groups"]

    def test_create_in_named_group(self, empty_client):
        """AC-10.48: POST with group='github' creates in access-rules.d/github.yaml."""
        resp = empty_client.post(
            "/api/access-rules",
            json={
                "id": "gh-rule",
                "domain": "api.github.com",
                "mode": "allow",
                "paths": ["^/repos/"],
                "group": "github",
            },
        )
        assert resp.status_code == 201

        listed = empty_client.get("/api/access-rules").json()
        assert "github" in listed["groups"]

    def test_create_duplicate_id(self, client):
        """AC-10.49: POST with duplicate ID returns 409."""
        resp = client.post(
            "/api/access-rules",
            json={
                "id": "github-allowlist",
                "domain": "other.com",
                "mode": "deny",
                "paths": [],
            },
        )
        assert resp.status_code == 409

    def test_create_duplicate_domain(self, client):
        """AC-10.50: POST with duplicate domain returns 409."""
        resp = client.post(
            "/api/access-rules",
            json={
                "id": "another-rule",
                "domain": "api.github.com",
                "mode": "deny",
                "paths": [],
            },
        )
        assert resp.status_code == 409

    def test_create_invalid_regex(self, empty_client):
        """AC-10.51: POST with invalid regex returns 422 (Pydantic validation)."""
        resp = empty_client.post(
            "/api/access-rules",
            json={
                "id": "bad-regex",
                "domain": "example.com",
                "mode": "allow",
                "paths": ["[invalid"],
            },
        )
        assert resp.status_code == 422

    def test_create_invalid_mode(self, empty_client):
        """AC-10.52: POST with invalid mode returns 422 (Pydantic Literal validation)."""
        resp = empty_client.post(
            "/api/access-rules",
            json={
                "id": "bad-mode",
                "domain": "example.com",
                "mode": "block",
                "paths": [],
            },
        )
        assert resp.status_code == 422


class TestUpdateAccessRule:
    def test_update_access_rule(self, client):
        """AC-10.53: PUT updates rule in its current group file."""
        resp = client.put(
            "/api/access-rules/github-allowlist",
            json={
                "mode": "deny",
                "paths": ["^/admin"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "deny"
        assert data["paths"] == ["^/admin"]

    def test_update_nonexistent(self, client):
        """AC-10.54: PUT on unknown ID returns 404."""
        resp = client.put(
            "/api/access-rules/nonexistent",
            json={
                "mode": "deny",
            },
        )
        assert resp.status_code == 404


class TestDeleteAccessRule:
    def test_delete_access_rule(self, client):
        """AC-10.55: DELETE removes the rule from its group file."""
        resp = client.delete("/api/access-rules/github-allowlist")
        assert resp.status_code == 204

        # Verify it's gone
        resp = client.get("/api/access-rules/github-allowlist")
        assert resp.status_code == 404

    def test_delete_last_rule_removes_file(self, tmp_path):
        """AC-10.56: DELETE last rule in a group file deletes the file."""
        d = tmp_path / "access-rules.d"
        d.mkdir()
        (d / "github.yaml").write_text("""access_rules:
  - id: gh-rule
    domain: api.github.com
    mode: allow
    paths: ["^/repos/"]
""")
        access_store = AccessRuleStore(tmp_path)
        cred_store = MockCredentialStore()
        pending = PendingRequestStore()
        app = create_app(cred_store, pending, access_store)
        c = TestClient(app)

        resp = c.delete("/api/access-rules/gh-rule")
        assert resp.status_code == 204

        # The file should be deleted
        assert not (d / "github.yaml").exists()

    def test_delete_nonexistent(self, client):
        """AC-10.57: DELETE on unknown ID returns 404."""
        resp = client.delete("/api/access-rules/nonexistent")
        assert resp.status_code == 404


class TestStatusEndpoint:
    def test_status_includes_access_count(self, client):
        """AC-10.58: /api/status includes total_access_rules and access_rule_groups."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_access_rules" in data
        assert "access_rule_groups" in data
        assert data["total_access_rules"] == 2
        assert data["access_rule_groups"] == 2
