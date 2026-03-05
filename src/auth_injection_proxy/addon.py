"""mitmproxy addon — entry point for mitmdump -s."""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any

import uvicorn
from mitmproxy import ctx, http

from auth_injection_proxy.agent_api.handlers import AgentApiHandler
from auth_injection_proxy.config import AppConfig, load_config
from auth_injection_proxy.injection.external_script import ExternalScriptManager
from auth_injection_proxy.injection.injector import inject_auth
from auth_injection_proxy.injection.oauth2 import OAuth2TokenManager
from auth_injection_proxy.logging import setup_logging
from auth_injection_proxy.matching.rules import RuleMatcher
from auth_injection_proxy.mgmt.app import create_app
from auth_injection_proxy.requests.pending import PendingRequestStore
from auth_injection_proxy.store.yaml_store import YamlCredentialStore
from auth_injection_proxy.stripping.response_strip import strip_secrets

logger = logging.getLogger(__name__)


class AuthInjectionAddon:
    """Main mitmproxy addon that wires all components together."""

    def __init__(self) -> None:
        self._matcher = RuleMatcher()
        self._oauth2 = OAuth2TokenManager()
        self._external_script = ExternalScriptManager()
        self._config_dir: str = "."
        self._store: YamlCredentialStore | None = None
        self._pending: PendingRequestStore | None = None
        self._agent_api: AgentApiHandler | None = None
        self._config: AppConfig | None = None
        self._injected_secrets: dict[int, list[str]] = {}
        self._mgmt_thread: threading.Thread | None = None
        self._watcher_task: asyncio.Task[None] | None = None

    def load(self, loader: Any) -> None:
        loader.add_option(
            name="config_path",
            typespec=str,
            default="config.yaml",
            help="Path to the auth-injection-proxy YAML config file",
        )

    def configure(self, updated: set[str]) -> None:
        if "config_path" not in updated:
            return

        config_path = ctx.options.config_path
        self._config_dir = str(Path(config_path).resolve().parent)
        setup_logging()

        try:
            self._config = load_config(config_path)
        except (FileNotFoundError, Exception) as e:
            logger.error("Failed to load config: %s", e)
            raise SystemExit(1) from e

        self._store = YamlCredentialStore(config_path)
        self._matcher.update_rules(list(self._store._rules))

        self._pending = PendingRequestStore(
            default_ttl=self._config.proxy.credential_request_ttl,
        )
        self._agent_api = AgentApiHandler(
            store=self._store,
            pending=self._pending,
            mgmt_port=self._config.proxy.mgmt_port,
        )

        # Start management API in daemon thread
        self._start_mgmt_api(self._config.proxy.mgmt_port)

        logger.info(
            "Auth injection proxy configured: %d rules, mgmt on :%d",
            len(self._config.credentials),
            self._config.proxy.mgmt_port,
        )

    def running(self) -> None:
        """Called when mitmproxy is fully started. Start file watcher."""
        if self._store:
            loop = asyncio.get_event_loop()
            self._watcher_task = loop.create_task(self._store.watch(self._on_rules_changed))

    def _on_rules_changed(self, rules: list) -> None:
        self._matcher.update_rules(rules)
        self._oauth2.clear()
        self._external_script.clear()
        logger.info("Rules reloaded: %d rules active", len(rules))

    async def request(self, flow: http.HTTPFlow) -> None:
        # Handle agent API requests first
        if self._agent_api and flow.request.pretty_host.startswith("__auth"):
            # Agent API is accessed via any host with /__auth/ path
            pass

        if self._agent_api:
            path = flow.request.path
            if path.startswith("/__auth/"):
                handled = await self._agent_api.handle(flow)
                if handled:
                    return

        # Match against rules
        host = flow.request.pretty_host
        path = flow.request.path
        rule = self._matcher.match(host, path)

        if rule is None:
            logger.info(
                "%s %s%s → no match (passthrough)",
                flow.request.method,
                host,
                path,
            )
            return

        # Inject auth
        secrets_list = await inject_auth(
            flow, rule, self._oauth2, self._external_script, self._config_dir
        )
        if secrets_list:
            self._injected_secrets[id(flow)] = secrets_list

        logger.info(
            "%s %s%s → rule=%s",
            flow.request.method,
            host,
            path,
            rule.id,
        )

    def response(self, flow: http.HTTPFlow) -> None:
        flow_id = id(flow)
        secrets_list = self._injected_secrets.pop(flow_id, [])
        if secrets_list:
            strip_secrets(flow, secrets_list)

        # Log response
        host = flow.request.pretty_host
        path = flow.request.path
        status = flow.response.status_code if flow.response else 0
        logger.info(
            "%s %s%s → %d",
            flow.request.method,
            host,
            path,
            status,
        )

    def done(self) -> None:
        if self._watcher_task:
            self._watcher_task.cancel()

    def _start_mgmt_api(self, port: int) -> None:
        if self._store is None or self._pending is None:
            return
        app = create_app(self._store, self._pending)

        def _run_mgmt() -> None:
            loop = asyncio.new_event_loop()
            config = uvicorn.Config(
                app,
                host="0.0.0.0",
                port=port,
                loop="none",
                log_level="warning",
            )
            server = uvicorn.Server(config)
            loop.run_until_complete(server.serve())

        self._mgmt_thread = threading.Thread(target=_run_mgmt, daemon=True)
        self._mgmt_thread.start()
        logger.info("Management API started on :%d", port)


addons = [AuthInjectionAddon()]
