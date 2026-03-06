"""AC-10, AC-12: Credential requests and polling tests."""

import time
from unittest.mock import patch

from auth_injection_proxy.requests.pending import PendingRequestStore, RequestStatus


class TestPendingRequestStore:
    def test_create_returns_token(self):
        """AC-10.1: Create returns setup_url, token, expires_in."""
        store = PendingRequestStore(default_ttl=900)
        req = store.create(domain="api.example.com", reason="Need access", auth_type="bearer")
        assert req.token
        assert len(req.token) >= 32
        assert req.domain == "api.example.com"
        assert req.auth_type == "bearer"
        assert req.ttl == 900

    def test_create_without_auth_type(self):
        """AC-10.2: Create without auth_type succeeds."""
        store = PendingRequestStore()
        req = store.create(domain="api.example.com", reason="test")
        assert req.auth_type is None

    def test_get_pending(self):
        """AC-12.1: Status is pending after creation."""
        store = PendingRequestStore()
        req = store.create(domain="d.com", reason="test")
        status = store.get_status(req.token)
        assert status == RequestStatus.PENDING

    def test_fulfill(self):
        """AC-12.2: Status is fulfilled after fulfill()."""
        store = PendingRequestStore()
        req = store.create(domain="d.com", reason="test")
        assert store.fulfill(req.token, "rule-1")
        assert store.get_status(req.token) == RequestStatus.FULFILLED

    def test_expired(self):
        """AC-12.3: Status is expired after TTL."""
        store = PendingRequestStore(default_ttl=1)
        req = store.create(domain="d.com", reason="test")
        # Simulate time passing
        with patch.object(time, "monotonic", return_value=req.created_at + 2):
            status = store.get_status(req.token)
        assert status == RequestStatus.EXPIRED

    def test_unknown_token(self):
        """AC-12.4: Unknown token returns None."""
        store = PendingRequestStore()
        assert store.get_status("nonexistent") is None

    def test_fulfill_expired_fails(self):
        """Cannot fulfill an expired request."""
        store = PendingRequestStore(default_ttl=1)
        req = store.create(domain="d.com", reason="test")
        with patch.object(time, "monotonic", return_value=req.created_at + 2):
            assert not store.fulfill(req.token, "rule-1")

    def test_fulfill_already_fulfilled_fails(self):
        """AC-14.6: Single-use — cannot fulfill twice."""
        store = PendingRequestStore()
        req = store.create(domain="d.com", reason="test")
        assert store.fulfill(req.token, "rule-1")
        assert not store.fulfill(req.token, "rule-2")

    def test_token_uniqueness(self):
        """AC-10.7: All tokens are unique."""
        store = PendingRequestStore()
        tokens = set()
        for _ in range(100):
            req = store.create(domain="d.com", reason="test")
            tokens.add(req.token)
        assert len(tokens) == 100

    def test_rate_limiting(self):
        """AC-10.6: Rate limiting kicks in after max_requests."""
        store = PendingRequestStore()
        # First 10 should pass
        for _ in range(10):
            assert store.check_rate_limit()
        # 11th should fail
        assert not store.check_rate_limit()

    def test_cleanup_expired(self):
        store = PendingRequestStore(default_ttl=0)
        store.create(domain="d.com", reason="test")
        with patch.object(time, "monotonic", return_value=time.monotonic() + 1):
            removed = store.cleanup_expired()
        assert removed == 1

    def test_create_with_webhook_url(self):
        """Webhook URL is stored on the request."""
        store = PendingRequestStore()
        req = store.create(
            domain="d.com", reason="test", webhook_url="https://hooks.example.com/whk_123"
        )
        assert req.webhook_url == "https://hooks.example.com/whk_123"

    def test_create_without_webhook_url(self):
        """Webhook URL defaults to None."""
        store = PendingRequestStore()
        req = store.create(domain="d.com", reason="test")
        assert req.webhook_url is None

    @patch("auth_injection_proxy.requests.pending._fire_webhook")
    def test_webhook_fires_on_fulfill(self, mock_fire):
        """Webhook is fired when a request is fulfilled."""
        store = PendingRequestStore()
        req = store.create(
            domain="api.example.com",
            reason="test",
            webhook_url="https://hooks.example.com/whk_123",
        )
        store.fulfill(req.token, "rule-1")

        # Wait for background thread
        import threading

        for t in threading.enumerate():
            if t.name != "MainThread" and t.daemon:
                t.join(timeout=1)

        mock_fire.assert_called_once_with(
            "https://hooks.example.com/whk_123",
            {"token": req.token, "status": "fulfilled", "domain": "api.example.com"},
        )

    @patch("auth_injection_proxy.requests.pending._fire_webhook")
    def test_no_webhook_without_url(self, mock_fire):
        """No webhook fired when webhook_url is not set."""
        store = PendingRequestStore()
        req = store.create(domain="d.com", reason="test")
        store.fulfill(req.token, "rule-1")

        import threading

        for t in threading.enumerate():
            if t.name != "MainThread" and t.daemon:
                t.join(timeout=1)

        mock_fire.assert_not_called()

    @patch("auth_injection_proxy.requests.pending._fire_webhook")
    def test_webhook_fires_on_expiry(self, mock_fire):
        """Webhook fires with status 'expired' when request expires."""
        store = PendingRequestStore(default_ttl=1)
        req = store.create(
            domain="api.example.com",
            reason="test",
            webhook_url="https://hooks.example.com/whk_123",
        )
        with patch.object(time, "monotonic", return_value=req.created_at + 2):
            store.get_status(req.token)

        import threading

        for t in threading.enumerate():
            if t.name != "MainThread" and t.daemon:
                t.join(timeout=1)

        mock_fire.assert_called_once_with(
            "https://hooks.example.com/whk_123",
            {"token": req.token, "status": "expired", "domain": "api.example.com"},
        )

    @patch("auth_injection_proxy.requests.pending._fire_webhook")
    def test_webhook_fires_on_cleanup_expiry(self, mock_fire):
        """Webhook fires when request expires during cleanup."""
        store = PendingRequestStore(default_ttl=0)
        req = store.create(
            domain="api.example.com",
            reason="test",
            webhook_url="https://hooks.example.com/whk_123",
        )
        with patch.object(time, "monotonic", return_value=time.monotonic() + 1):
            store.cleanup_expired()

        import threading

        for t in threading.enumerate():
            if t.name != "MainThread" and t.daemon:
                t.join(timeout=1)

        mock_fire.assert_called_once_with(
            "https://hooks.example.com/whk_123",
            {"token": req.token, "status": "expired", "domain": "api.example.com"},
        )
