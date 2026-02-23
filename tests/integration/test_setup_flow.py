"""AC-11: Setup UI end-to-end tests."""

import pytest
from fastapi.testclient import TestClient

from auth_injection_proxy.mgmt.app import create_app
from auth_injection_proxy.requests.pending import PendingRequestStore
from tests.conftest import MockCredentialStore


@pytest.fixture
def setup_env():
    store = MockCredentialStore()
    pending = PendingRequestStore(default_ttl=900)
    app = create_app(store, pending)
    client = TestClient(app)
    return store, pending, client


class TestSetupFlow:
    def test_get_setup_page(self, setup_env):
        """AC-11.1/11.2: Setup page renders with correct fields."""
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="Need access", auth_type="bearer")
        resp = client.get(f"/setup/{req.token}")
        assert resp.status_code == 200
        assert "api.example.com" in resp.text
        assert "bearer" in resp.text

    def test_get_setup_no_auth_type(self, setup_env):
        """AC-11.2: No pre-selection when auth_type not provided."""
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="test")
        resp = client.get(f"/setup/{req.token}")
        assert resp.status_code == 200

    def test_submit_bearer(self, setup_env):
        """AC-11.4: Submit creates credential and marks fulfilled."""
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="test", auth_type="bearer")
        resp = client.post(
            f"/setup/{req.token}",
            data={"auth_type": "bearer", "token": "sk-test-123"},
        )
        assert resp.status_code == 200
        assert "configured" in resp.text.lower() or "created" in resp.text.lower()

        # Verify rule was created in store
        import asyncio

        rules = asyncio.get_event_loop().run_until_complete(store.list())
        assert len(rules) == 1
        assert rules[0].domain == "api.example.com"

        # Verify status is fulfilled
        from auth_injection_proxy.requests.pending import RequestStatus

        assert pending.get_status(req.token) == RequestStatus.FULFILLED

    def test_submit_empty_token_rejected(self, setup_env):
        """AC-11.5: Empty token → validation error."""
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="test", auth_type="bearer")
        resp = client.post(
            f"/setup/{req.token}",
            data={"auth_type": "bearer", "token": ""},
        )
        assert resp.status_code == 400

    def test_expired_token(self, setup_env):
        """AC-11.6: Expired token → 410."""
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="test", ttl=0)
        # Force expiry by backdating the created_at
        req.created_at = req.created_at - 1
        resp = client.get(f"/setup/{req.token}")
        assert resp.status_code == 410

    def test_already_fulfilled(self, setup_env):
        """AC-11.7: Already used token → 410."""
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="test", auth_type="bearer")
        # Fulfill it first
        client.post(
            f"/setup/{req.token}",
            data={"auth_type": "bearer", "token": "sk-123"},
        )
        # Try again
        resp = client.get(f"/setup/{req.token}")
        assert resp.status_code == 410

    def test_unknown_token(self, setup_env):
        """AC-11.8: Unknown token → 404."""
        _, _, client = setup_env
        resp = client.get("/setup/nonexistent-token")
        assert resp.status_code == 404

    def test_submit_basic(self, setup_env):
        """Submit basic auth."""
        store, pending, client = setup_env
        req = pending.create(domain="jira.example.com", reason="test", auth_type="basic")
        resp = client.post(
            f"/setup/{req.token}",
            data={"auth_type": "basic", "username": "user", "password": "pass"},
        )
        assert resp.status_code == 200

    def test_submit_header(self, setup_env):
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="test", auth_type="header")
        resp = client.post(
            f"/setup/{req.token}",
            data={"auth_type": "header", "header_name": "X-Key", "header_value": "val"},
        )
        assert resp.status_code == 200

    def test_submit_query_param(self, setup_env):
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="test", auth_type="query_param")
        resp = client.post(
            f"/setup/{req.token}",
            data={"auth_type": "query_param", "param_name": "key", "param_value": "val"},
        )
        assert resp.status_code == 200

    def test_submit_no_auth_type(self, setup_env):
        """No auth type selected → error."""
        store, pending, client = setup_env
        req = pending.create(domain="api.example.com", reason="test")
        resp = client.post(
            f"/setup/{req.token}",
            data={"auth_type": ""},
        )
        assert resp.status_code == 400
