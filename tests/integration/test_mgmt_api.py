"""AC-6: Management API CRUD integration tests."""

import pytest
from fastapi.testclient import TestClient

from auth_injection_proxy.matching.models import BearerAuth, CredentialRule
from auth_injection_proxy.mgmt.app import create_app
from auth_injection_proxy.requests.pending import PendingRequestStore
from tests.conftest import MockCredentialStore


@pytest.fixture
def client():
    store = MockCredentialStore(
        [
            CredentialRule(
                id="openai",
                domain="api.openai.com",
                path_prefix="/v1/",
                auth=BearerAuth(type="bearer", token="sk-secret-token-xyz"),
            ),
        ]
    )
    pending = PendingRequestStore()
    app = create_app(store, pending)
    return TestClient(app)


@pytest.fixture
def empty_client():
    store = MockCredentialStore()
    pending = PendingRequestStore()
    app = create_app(store, pending)
    return TestClient(app)


class TestListCredentials:
    def test_list_with_masking(self, client):
        """AC-6.1: Secrets are masked in list response."""
        resp = client.get("/api/credentials")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["id"] == "openai"
        assert "***" in data[0]["auth"]["token"]
        assert "sk-secret-token-xyz" not in data[0]["auth"]["token"]


class TestCreateCredential:
    def test_create(self, empty_client):
        """AC-6.2: Create writes to store."""
        resp = empty_client.post(
            "/api/credentials",
            json={
                "id": "new-rule",
                "domain": "example.com",
                "auth": {"type": "bearer", "token": "tok-123"},
            },
        )
        assert resp.status_code == 201
        # Verify listed
        listed = empty_client.get("/api/credentials").json()
        assert len(listed) == 1

    def test_duplicate_id(self, client):
        """AC-6.3: Duplicate ID → 409."""
        resp = client.post(
            "/api/credentials",
            json={
                "id": "openai",
                "domain": "other.com",
                "auth": {"type": "bearer", "token": "t"},
            },
        )
        assert resp.status_code == 409

    def test_invalid_auth_type(self, empty_client):
        """AC-6.4: Invalid auth type → 400 (via Pydantic validation)."""
        resp = empty_client.post(
            "/api/credentials",
            json={
                "id": "bad",
                "domain": "example.com",
                "auth": {"type": "kerberos"},
            },
        )
        assert resp.status_code == 422

    def test_missing_domain(self, empty_client):
        """AC-6.5: Missing required field → 422."""
        resp = empty_client.post(
            "/api/credentials",
            json={
                "id": "bad",
                "auth": {"type": "bearer", "token": "t"},
            },
        )
        assert resp.status_code == 422


class TestUpdateCredential:
    def test_update(self, client):
        """AC-6.6: Update changes the rule."""
        resp = client.put(
            "/api/credentials/openai",
            json={
                "auth": {"type": "bearer", "token": "new-token"},
            },
        )
        assert resp.status_code == 200

    def test_update_nonexistent(self, client):
        """AC-6.7: Update unknown → 404."""
        resp = client.put(
            "/api/credentials/unknown",
            json={
                "auth": {"type": "bearer", "token": "t"},
            },
        )
        assert resp.status_code == 404


class TestDeleteCredential:
    def test_delete(self, client):
        """AC-6.8: Delete removes the rule."""
        resp = client.delete("/api/credentials/openai")
        assert resp.status_code == 204
        listed = client.get("/api/credentials").json()
        assert len(listed) == 0

    def test_delete_nonexistent(self, client):
        """AC-6.9: Delete unknown → 404."""
        resp = client.delete("/api/credentials/unknown")
        assert resp.status_code == 404


class TestStatusEndpoint:
    def test_status(self, client):
        """AC-6.12: Status endpoint returns stats."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["total_rules"] == 1
        assert data["enabled_rules"] == 1
        assert "uptime_seconds" in data
