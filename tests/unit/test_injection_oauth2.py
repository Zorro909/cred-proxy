"""AC-8: OAuth2 client_credentials lifecycle tests."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_injection_proxy.injection.oauth2 import OAuth2TokenManager
from tests.conftest import make_flow


def _mock_httpx_client(token_data=None, side_effect=None):
    """Create a patched httpx.AsyncClient context manager."""
    mock_client = AsyncMock()
    if side_effect:
        mock_client.post.side_effect = side_effect
    else:
        mock_resp = MagicMock()
        mock_resp.json.return_value = token_data or {
            "access_token": "tok",
            "expires_in": 3600,
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_resp
    return mock_client


class TestOAuth2TokenManager:
    @pytest.fixture
    def manager(self):
        return OAuth2TokenManager()

    def _patch_client(self, mock_client):
        patcher = patch("auth_injection_proxy.injection.oauth2.httpx.AsyncClient")
        mock_cls = patcher.start()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        return patcher

    async def test_initial_token_acquisition(self, manager):
        """AC-8.1: First request acquires token."""
        flow = make_flow("https://api.service.com/data")
        mock_client = _mock_httpx_client({"access_token": "tok-abc", "expires_in": 3600})
        patcher = self._patch_client(mock_client)
        try:
            secrets = await manager.inject(
                flow, "r1", "https://auth.example.com/token", "cid", "csecret", ["read"]
            )
        finally:
            patcher.stop()

        assert flow.request.headers["Authorization"] == "Bearer tok-abc"
        assert "tok-abc" in secrets
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[1]["data"]["scope"] == "read"

    async def test_token_caching(self, manager):
        """AC-8.2: Second request uses cached token."""
        flow1 = make_flow("https://api.service.com/data")
        flow2 = make_flow("https://api.service.com/data")
        mock_client = _mock_httpx_client({"access_token": "tok-cached", "expires_in": 3600})
        patcher = self._patch_client(mock_client)
        try:
            await manager.inject(
                flow1, "r1", "https://auth.example.com/token", "cid", "csecret", []
            )
            await manager.inject(
                flow2, "r1", "https://auth.example.com/token", "cid", "csecret", []
            )
        finally:
            patcher.stop()

        assert mock_client.post.call_count == 1
        assert flow2.request.headers["Authorization"] == "Bearer tok-cached"

    async def test_no_scopes_omits_param(self, manager):
        """AC-8.5: No scopes → no scope in POST body."""
        flow = make_flow("https://api.service.com/data")
        mock_client = _mock_httpx_client({"access_token": "tok", "expires_in": 3600})
        patcher = self._patch_client(mock_client)
        try:
            await manager.inject(flow, "r1", "https://auth.example.com/token", "cid", "csecret", [])
        finally:
            patcher.stop()

        call_data = mock_client.post.call_args[1]["data"]
        assert "scope" not in call_data

    async def test_acquisition_failure_passthrough(self, manager):
        """AC-8.7: Token failure → no auth injected."""
        flow = make_flow("https://api.service.com/data")
        mock_client = _mock_httpx_client(side_effect=Exception("connection failed"))
        patcher = self._patch_client(mock_client)
        try:
            secrets = await manager.inject(
                flow, "r1", "https://auth.example.com/token", "cid", "csecret", []
            )
        finally:
            patcher.stop()

        assert secrets == []
        assert "Authorization" not in flow.request.headers

    async def test_retry_after_failure(self, manager):
        """AC-8.8: After failure, next request retries."""
        mock_client = _mock_httpx_client(side_effect=Exception("fail"))
        patcher = self._patch_client(mock_client)
        try:
            # First call fails
            flow1 = make_flow("https://api.service.com/data")
            await manager.inject(
                flow1, "r1", "https://auth.example.com/token", "cid", "csecret", []
            )

            # Second call succeeds — replace the side_effect
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"access_token": "tok-retry", "expires_in": 3600}
            mock_resp.raise_for_status = MagicMock()
            mock_client.post.side_effect = None
            mock_client.post.return_value = mock_resp

            flow2 = make_flow("https://api.service.com/data")
            secrets = await manager.inject(
                flow2, "r1", "https://auth.example.com/token", "cid", "csecret", []
            )
        finally:
            patcher.stop()

        assert "tok-retry" in secrets

    def test_clear_specific_rule(self, manager):
        """Token cache can be cleared per-rule."""
        manager._tokens["r1"] = object()  # type: ignore[assignment]
        manager._tokens["r2"] = object()  # type: ignore[assignment]
        manager.clear("r1")
        assert "r1" not in manager._tokens
        assert "r2" in manager._tokens

    def test_clear_all(self, manager):
        manager._tokens["r1"] = object()  # type: ignore[assignment]
        manager.clear()
        assert len(manager._tokens) == 0
