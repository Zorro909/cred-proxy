"""OAuth2 client_credentials flow with token caching and locking."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx
from mitmproxy import http

logger = logging.getLogger(__name__)


class _CachedToken:
    __slots__ = ("access_token", "expires_at")

    def __init__(self, access_token: str, expires_at: float) -> None:
        self.access_token = access_token
        self.expires_at = expires_at

    def is_valid(self) -> bool:
        return time.monotonic() < self.expires_at


class OAuth2TokenManager:
    """Manages OAuth2 client_credentials tokens with per-rule locking."""

    def __init__(self) -> None:
        self._tokens: dict[str, _CachedToken] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, rule_id: str) -> asyncio.Lock:
        if rule_id not in self._locks:
            self._locks[rule_id] = asyncio.Lock()
        return self._locks[rule_id]

    async def inject(
        self,
        flow: http.HTTPFlow,
        rule_id: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        scopes: list[str],
    ) -> list[str]:
        """Acquire token (cached or fresh) and inject as Bearer. Returns secrets."""
        token = await self._get_token(rule_id, token_url, client_id, client_secret, scopes)
        if token is None:
            return []
        flow.request.headers["Authorization"] = f"Bearer {token}"
        return [token]

    async def _get_token(
        self,
        rule_id: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        scopes: list[str],
    ) -> str | None:
        cached = self._tokens.get(rule_id)
        if cached and cached.is_valid():
            return cached.access_token

        lock = self._get_lock(rule_id)
        async with lock:
            # Double-check after acquiring lock
            cached = self._tokens.get(rule_id)
            if cached and cached.is_valid():
                return cached.access_token

            return await self._acquire_token(rule_id, token_url, client_id, client_secret, scopes)

    async def _acquire_token(
        self,
        rule_id: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        scopes: list[str],
    ) -> str | None:
        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scopes:
            data["scope"] = " ".join(scopes)

        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                resp = await client.post(token_url, data=data)
                resp.raise_for_status()
                body = resp.json()
                access_token: str = body["access_token"]
                expires_in = int(body.get("expires_in", 3600))
                # Shave 30s off TTL to avoid edge-of-expiry races
                self._tokens[rule_id] = _CachedToken(
                    access_token=access_token,
                    expires_at=time.monotonic() + max(expires_in - 30, 0),
                )
                logger.info(
                    "OAuth2 token acquired for rule %s (expires in %ds)", rule_id, expires_in
                )
                return access_token
        except Exception:
            logger.exception("OAuth2 token acquisition failed for rule %s", rule_id)
            # Remove stale cache on failure so next request retries
            self._tokens.pop(rule_id, None)
            return None

    def clear(self, rule_id: str | None = None) -> None:
        """Clear cached tokens. If rule_id given, clear only that rule."""
        if rule_id:
            self._tokens.pop(rule_id, None)
        else:
            self._tokens.clear()
