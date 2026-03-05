"""External script credential provider tests."""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, patch

import pytest

from auth_injection_proxy.injection.external_script import ExternalScriptManager
from tests.conftest import make_flow


def _make_proc_result(stdout: str = "", stderr: str = "", returncode: int = 0) -> AsyncMock:
    """Create a mock completed process."""
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout.encode(), stderr.encode()))
    return proc


class TestExternalScriptManager:
    @pytest.fixture
    def manager(self) -> ExternalScriptManager:
        return ExternalScriptManager()

    async def test_successful_injection(self, manager: ExternalScriptManager):
        """Script outputs headers → headers injected into flow."""
        flow = make_flow("https://api.github.com/repos")
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer ghp_abc123"},
            }
        )
        proc = _make_proc_result(stdout=output)

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            secrets = await manager.inject(flow, "r1", "./script.sh", {}, 3600, "/config")

        assert flow.request.headers["Authorization"] == "Bearer ghp_abc123"
        assert "Bearer ghp_abc123" in secrets

    async def test_multiple_headers(self, manager: ExternalScriptManager):
        """Script can inject multiple headers."""
        flow = make_flow("https://api.example.com/data")
        output = json.dumps(
            {
                "headers": {
                    "Authorization": "Bearer tok",
                    "X-Custom": "custom-val",
                },
            }
        )
        proc = _make_proc_result(stdout=output)

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            secrets = await manager.inject(flow, "r1", "./script.sh", {}, 3600, "/config")

        assert flow.request.headers["Authorization"] == "Bearer tok"
        assert flow.request.headers["X-Custom"] == "custom-val"
        assert "Bearer tok" in secrets
        assert "custom-val" in secrets

    async def test_refresh_in_override(self, manager: ExternalScriptManager):
        """Script outputs refresh_in → overrides default interval."""
        flow = make_flow("https://api.github.com/repos")
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer tok"},
                "refresh_in": 60,
            }
        )
        proc = _make_proc_result(stdout=output)

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            await manager.inject(flow, "r1", "./script.sh", {}, 3600, "/config")

        cached = manager._cache.get("r1")
        assert cached is not None
        # refresh_in=60 minus 30s buffer = 30s from now
        assert cached.expires_at <= time.monotonic() + 31

    async def test_script_failure_returns_empty(self, manager: ExternalScriptManager):
        """Non-zero exit code → empty secrets, no headers injected."""
        flow = make_flow("https://api.github.com/repos")
        proc = _make_proc_result(returncode=1, stderr="error occurred")

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            secrets = await manager.inject(flow, "r1", "./script.sh", {}, 3600, "/config")

        assert secrets == []
        assert "Authorization" not in flow.request.headers

    async def test_script_timeout(self, manager: ExternalScriptManager):
        """Script timeout → treated as failure."""
        flow = make_flow("https://api.github.com/repos")

        async def slow_communicate():
            raise TimeoutError

        proc = AsyncMock()
        proc.communicate = slow_communicate

        with (
            patch(
                "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
            patch(
                "auth_injection_proxy.injection.external_script.asyncio.wait_for",
                side_effect=TimeoutError,
            ),
        ):
            secrets = await manager.inject(flow, "r1", "./script.sh", {}, 3600, "/config")

        assert secrets == []

    async def test_caching(self, manager: ExternalScriptManager):
        """Second call within interval reuses cached result."""
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer cached-tok"},
            }
        )
        proc = _make_proc_result(stdout=output)
        call_count = 0

        async def mock_create(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return proc

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            side_effect=mock_create,
        ):
            flow1 = make_flow("https://api.github.com/repos")
            await manager.inject(flow1, "r1", "./script.sh", {}, 3600, "/config")
            flow2 = make_flow("https://api.github.com/repos")
            await manager.inject(flow2, "r1", "./script.sh", {}, 3600, "/config")

        assert call_count == 1
        assert flow2.request.headers["Authorization"] == "Bearer cached-tok"

    async def test_cache_expiry(self, manager: ExternalScriptManager):
        """Call after expiry re-runs script."""
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer tok"},
            }
        )
        proc = _make_proc_result(stdout=output)
        call_count = 0

        async def mock_create(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return proc

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            side_effect=mock_create,
        ):
            flow1 = make_flow("https://api.github.com/repos")
            await manager.inject(flow1, "r1", "./script.sh", {}, 3600, "/config")
            # Expire the cache
            manager._cache["r1"].expires_at = time.monotonic() - 1

            flow2 = make_flow("https://api.github.com/repos")
            await manager.inject(flow2, "r1", "./script.sh", {}, 3600, "/config")

        assert call_count == 2

    async def test_clear_all(self, manager: ExternalScriptManager):
        """clear() evicts all cached results."""
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer tok"},
            }
        )
        proc = _make_proc_result(stdout=output)

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            flow = make_flow("https://api.github.com/repos")
            await manager.inject(flow, "r1", "./script.sh", {}, 3600, "/config")

        assert "r1" in manager._cache
        manager.clear()
        assert "r1" not in manager._cache

    async def test_clear_specific_rule(self, manager: ExternalScriptManager):
        """clear(rule_id) evicts only that rule."""
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer tok"},
            }
        )
        proc = _make_proc_result(stdout=output)

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            flow1 = make_flow("https://api.github.com/repos")
            await manager.inject(flow1, "r1", "./script.sh", {}, 3600, "/config")
            flow2 = make_flow("https://api.other.com/data")
            await manager.inject(flow2, "r2", "./other.sh", {}, 3600, "/config")

        manager.clear("r1")
        assert "r1" not in manager._cache
        assert "r2" in manager._cache

    async def test_env_vars_passed(self, manager: ExternalScriptManager):
        """Configured env vars are passed to the script."""
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer tok"},
            }
        )
        proc = _make_proc_result(stdout=output)
        captured_env = {}

        async def mock_create(*args, **kwargs):
            captured_env.update(kwargs.get("env", {}))
            return proc

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            side_effect=mock_create,
        ):
            flow = make_flow("https://api.github.com/repos")
            await manager.inject(
                flow,
                "r1",
                "./script.sh",
                {"GITHUB_APP_ID": "12345", "CUSTOM_VAR": "val"},
                3600,
                "/config",
            )

        assert captured_env["GITHUB_APP_ID"] == "12345"
        assert captured_env["CUSTOM_VAR"] == "val"

    async def test_invalid_json_output(self, manager: ExternalScriptManager):
        """Invalid JSON stdout → failure."""
        flow = make_flow("https://api.github.com/repos")
        proc = _make_proc_result(stdout="not json")

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            secrets = await manager.inject(flow, "r1", "./script.sh", {}, 3600, "/config")

        assert secrets == []

    async def test_missing_headers_key(self, manager: ExternalScriptManager):
        """JSON without 'headers' dict → failure."""
        flow = make_flow("https://api.github.com/repos")
        output = json.dumps({"token": "abc"})
        proc = _make_proc_result(stdout=output)

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            secrets = await manager.inject(flow, "r1", "./script.sh", {}, 3600, "/config")

        assert secrets == []

    async def test_relative_script_path(self, manager: ExternalScriptManager):
        """Relative script path resolved against config_dir."""
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer tok"},
            }
        )
        proc = _make_proc_result(stdout=output)
        captured_args: list[tuple] = []

        async def mock_create(*args, **kwargs):
            captured_args.append(args)
            return proc

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            side_effect=mock_create,
        ):
            flow = make_flow("https://api.github.com/repos")
            await manager.inject(flow, "r1", "./scripts/token.sh", {}, 3600, "/etc/proxy")

        assert captured_args[0][0] == "/etc/proxy/scripts/token.sh"

    async def test_absolute_script_path(self, manager: ExternalScriptManager):
        """Absolute script path used as-is."""
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer tok"},
            }
        )
        proc = _make_proc_result(stdout=output)
        captured_args: list[tuple] = []

        async def mock_create(*args, **kwargs):
            captured_args.append(args)
            return proc

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            side_effect=mock_create,
        ):
            flow = make_flow("https://api.github.com/repos")
            await manager.inject(flow, "r1", "/usr/local/bin/token.sh", {}, 3600, "/config")

        assert captured_args[0][0] == "/usr/local/bin/token.sh"

    async def test_failure_evicts_stale_cache(self, manager: ExternalScriptManager):
        """Script failure after a cached result evicts the stale entry."""
        output = json.dumps(
            {
                "headers": {"Authorization": "Bearer tok"},
            }
        )
        good_proc = _make_proc_result(stdout=output)
        bad_proc = _make_proc_result(returncode=1)

        calls = 0

        async def mock_create(*args, **kwargs):
            nonlocal calls
            calls += 1
            return good_proc if calls == 1 else bad_proc

        with patch(
            "auth_injection_proxy.injection.external_script.asyncio.create_subprocess_exec",
            side_effect=mock_create,
        ):
            # First call succeeds
            flow1 = make_flow("https://api.github.com/repos")
            await manager.inject(flow1, "r1", "./script.sh", {}, 3600, "/config")
            assert "r1" in manager._cache

            # Expire the cache
            manager._cache["r1"].expires_at = time.monotonic() - 1

            # Second call fails → cache evicted
            flow2 = make_flow("https://api.github.com/repos")
            await manager.inject(flow2, "r1", "./script.sh", {}, 3600, "/config")
            assert "r1" not in manager._cache
