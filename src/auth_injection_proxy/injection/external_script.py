"""External script credential provider with caching and locking."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from mitmproxy import http

logger = logging.getLogger(__name__)

_SCRIPT_TIMEOUT = 30  # seconds


class _CachedResult:
    __slots__ = ("headers", "expires_at")

    def __init__(self, headers: dict[str, str], expires_at: float) -> None:
        self.headers = headers
        self.expires_at = expires_at

    def is_valid(self) -> bool:
        return time.monotonic() < self.expires_at


class ExternalScriptManager:
    """Manages credentials obtained from external scripts with per-rule locking."""

    def __init__(self) -> None:
        self._cache: dict[str, _CachedResult] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, rule_id: str) -> asyncio.Lock:
        if rule_id not in self._locks:
            self._locks[rule_id] = asyncio.Lock()
        return self._locks[rule_id]

    async def inject(
        self,
        flow: http.HTTPFlow,
        rule_id: str,
        script: str,
        env: dict[str, str],
        refresh_interval: int,
        config_dir: str,
    ) -> list[str]:
        """Run script (cached), inject headers into flow. Returns secret values."""
        cached = self._cache.get(rule_id)
        if cached and cached.is_valid():
            return self._apply_headers(flow, cached.headers)

        lock = self._get_lock(rule_id)
        async with lock:
            # Double-check after acquiring lock
            cached = self._cache.get(rule_id)
            if cached and cached.is_valid():
                return self._apply_headers(flow, cached.headers)

            result = await self._run_script(rule_id, script, env, refresh_interval, config_dir)
            if result is None:
                return []
            return self._apply_headers(flow, result.headers)

    async def _run_script(
        self,
        rule_id: str,
        script: str,
        env: dict[str, str],
        refresh_interval: int,
        config_dir: str,
    ) -> _CachedResult | None:
        if os.path.isabs(script):
            script_path = script
        else:
            script_path = os.path.normpath(os.path.join(config_dir, script))

        # Build env: inherit current env + configured vars
        proc_env = dict(os.environ)
        proc_env.update(env)

        try:
            proc = await asyncio.create_subprocess_exec(
                script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=proc_env,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_SCRIPT_TIMEOUT)
        except TimeoutError:
            logger.error("External script timed out for rule %s: %s", rule_id, script_path)
            self._cache.pop(rule_id, None)
            return None
        except Exception:
            logger.exception("External script failed to execute for rule %s", rule_id)
            self._cache.pop(rule_id, None)
            return None

        if stderr:
            stderr_text = stderr.decode(errors="replace")
            logger.debug("External script stderr for rule %s: %s", rule_id, stderr_text)

        if proc.returncode != 0:
            logger.error(
                "External script exited %d for rule %s: %s",
                proc.returncode,
                rule_id,
                script_path,
            )
            self._cache.pop(rule_id, None)
            return None

        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError) as e:
            logger.error("External script output not valid JSON for rule %s: %s", rule_id, e)
            self._cache.pop(rule_id, None)
            return None

        headers = data.get("headers")
        if not isinstance(headers, dict):
            logger.error("External script output missing 'headers' dict for rule %s", rule_id)
            self._cache.pop(rule_id, None)
            return None

        refresh_in = data.get("refresh_in", refresh_interval)
        try:
            refresh_in = int(refresh_in)
        except (TypeError, ValueError):
            refresh_in = refresh_interval

        # Shave 30s off TTL to avoid edge-of-expiry races (same as oauth2)
        result = _CachedResult(
            headers=headers,
            expires_at=time.monotonic() + max(refresh_in - 30, 0),
        )
        self._cache[rule_id] = result
        logger.info(
            "External script credentials acquired for rule %s (refresh in %ds)",
            rule_id,
            refresh_in,
        )
        return result

    def clear(self, rule_id: str | None = None) -> None:
        """Clear cached results. If rule_id given, clear only that rule."""
        if rule_id:
            self._cache.pop(rule_id, None)
        else:
            self._cache.clear()

    @staticmethod
    def _apply_headers(flow: http.HTTPFlow, headers: dict[str, str]) -> list[str]:
        secrets: list[str] = []
        for name, value in headers.items():
            flow.request.headers[name] = value
            secrets.append(value)
        return secrets
