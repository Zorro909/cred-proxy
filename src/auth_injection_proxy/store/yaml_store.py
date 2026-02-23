"""YAML file backend for credential storage with hot-reload."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import ValidationError

from auth_injection_proxy.matching.models import CredentialRule
from auth_injection_proxy.store.interface import CredentialStore, RuleList

logger = logging.getLogger(__name__)


class YamlCredentialStore(CredentialStore):
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._rules: list[CredentialRule] = []
        self._load()

    def _load(self) -> list[CredentialRule]:
        """Load rules from YAML file. Returns the loaded rules."""
        if not self._path.exists():
            self._rules = []
            return self._rules
        try:
            text = self._path.read_text()
            data = yaml.safe_load(text)
            if data is None or "credentials" not in data:
                self._rules = []
                return self._rules
            rules = [CredentialRule.model_validate(r) for r in data["credentials"]]
            self._rules = rules
            logger.info("Loaded %d credential rules from %s", len(rules), self._path)
        except (yaml.YAMLError, ValidationError):
            logger.exception(
                "Failed to load credentials from %s, keeping previous rules", self._path
            )
        return self._rules

    def _save(self) -> None:
        """Atomically write rules to YAML file via temp file + os.replace."""
        data = {"credentials": [r.model_dump() for r in self._rules]}
        dir_path = self._path.parent
        dir_path.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix=".yaml.tmp")
        try:
            with os.fdopen(fd, "w") as f:
                yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
            os.replace(tmp_path, str(self._path))
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    async def list(self) -> RuleList:
        return [*self._rules]

    async def get(self, rule_id: str) -> CredentialRule | None:
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    async def create(self, rule: CredentialRule) -> None:
        for existing in self._rules:
            if existing.id == rule.id:
                raise ValueError(f"Credential with id '{rule.id}' already exists")
        self._rules.append(rule)
        self._save()

    async def update(self, rule_id: str, rule: CredentialRule) -> None:
        for i, existing in enumerate(self._rules):
            if existing.id == rule_id:
                self._rules[i] = rule
                self._save()
                return
        raise KeyError(f"Credential '{rule_id}' not found")

    async def delete(self, rule_id: str) -> None:
        for i, existing in enumerate(self._rules):
            if existing.id == rule_id:
                self._rules.pop(i)
                self._save()
                return
        raise KeyError(f"Credential '{rule_id}' not found")

    async def watch(self, callback: Callable[[RuleList], None]) -> None:
        """Watch the YAML file for changes using watchfiles."""
        from watchfiles import awatch

        logger.info("Starting file watcher for %s", self._path)
        async for _changes in awatch(self._path):
            logger.info("Detected change in %s, reloading", self._path)
            old_rules = [*self._rules]
            self._load()
            if self._rules != old_rules:
                try:
                    callback(self._rules)
                except Exception:
                    logger.exception("Error in watch callback")

    def reload(self) -> RuleList:
        """Manually trigger a reload. Returns the new rules list."""
        return self._load()

    async def start_watching(self, callback: Callable[[RuleList], None]) -> asyncio.Task[None]:
        """Start watching in a background task. Returns the task."""
        task = asyncio.create_task(self.watch(callback))
        return task
