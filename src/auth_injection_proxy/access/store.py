"""YAML-based access rule storage with drop-in directory support."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import ValidationError

from auth_injection_proxy.access.models import AccessRule

logger = logging.getLogger(__name__)


class AccessRuleGroup:
    """A group of access rules loaded from a single file."""

    def __init__(self, name: str, path: Path, rules: list[AccessRule]) -> None:
        self.name = name
        self.path = path
        self.rules = rules


class AccessRuleStore:
    def __init__(self, config_dir: str | Path) -> None:
        self._config_dir = Path(config_dir)
        self._main_file = self._config_dir / "access-rules.yaml"
        self._drop_in_dir = self._config_dir / "access-rules.d"
        self._groups: dict[str, AccessRuleGroup] = {}
        self._load()

    def _load(self) -> list[AccessRule]:
        """Load and merge rules from main file + drop-in directory.

        Raises ValueError on any parse error — callers (reload/watch) catch
        this and keep the previous rules active.
        """
        groups: dict[str, AccessRuleGroup] = {}

        # 1. Load main file as group "default"
        if self._main_file.exists():
            rules = self._load_file(self._main_file)
            groups["default"] = AccessRuleGroup("default", self._main_file, rules)

        # 2. Load drop-in files — group name = filename stem
        if self._drop_in_dir.is_dir():
            for f in sorted(self._drop_in_dir.glob("*.yaml")):
                group_name = f.stem
                rules = self._load_file(f)
                groups[group_name] = AccessRuleGroup(group_name, f, rules)

        # 3. Validate merged: no duplicate IDs, no duplicate domains
        all_rules = self._all_rules_from_groups(groups)
        self._validate_merged(all_rules)
        self._groups = groups
        logger.info(
            "Loaded %d access rules in %d groups from %s",
            len(all_rules),
            len(groups),
            self._config_dir,
        )
        return all_rules

    @staticmethod
    def _all_rules_from_groups(groups: dict[str, AccessRuleGroup]) -> list[AccessRule]:
        """Flatten all groups into a single ordered list."""
        result: list[AccessRule] = []
        for group in groups.values():
            result.extend(group.rules)
        return result

    def _load_file(self, path: Path) -> list[AccessRule]:
        """Load access rules from a single YAML file.

        Raises ValueError if parsing fails — the caller aborts the entire
        reload so that previously active rules are not silently dropped.
        """
        try:
            text = path.read_text()
            data = yaml.safe_load(text)
            if data is None or "access_rules" not in data:
                return []
            return [AccessRule.model_validate(r) for r in data["access_rules"]]
        except (yaml.YAMLError, ValidationError) as e:
            raise ValueError(f"Failed to load access rules from {path}: {e}") from e

    def _validate_merged(self, rules: list[AccessRule]) -> None:
        """Check for duplicate IDs and duplicate domains across all files."""
        ids = [r.id for r in rules]
        dupes = {x for x in ids if ids.count(x) > 1}
        if dupes:
            raise ValueError(f"Duplicate access rule IDs (across files): {dupes}")

        domains = [r.domain.lower() for r in rules]
        dupes = {x for x in domains if domains.count(x) > 1}
        if dupes:
            raise ValueError(f"Duplicate access rule domains (across files): {dupes}")

    def _save_group(self, group_name: str) -> None:
        """Atomically write a group's rules to its file."""
        group = self._groups.get(group_name)
        if group is None:
            raise KeyError(f"Group '{group_name}' not found")

        data = {"access_rules": [r.model_dump() for r in group.rules]}
        group.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(group.path.parent), suffix=".yaml.tmp")
        try:
            with os.fdopen(fd, "w") as f:
                yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
            os.replace(tmp_path, str(group.path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _resolve_group_path(self, group_name: str) -> Path:
        """Resolve the file path for a group name."""
        if group_name == "default":
            return self._main_file
        return self._drop_in_dir / f"{group_name}.yaml"

    @property
    def rules(self) -> list[AccessRule]:
        """Flat list of all rules across all groups."""
        return self._all_rules_from_groups(self._groups)

    @property
    def groups(self) -> dict[str, list[AccessRule]]:
        """Rules grouped by file: {group_name: [rules]}."""
        return {name: list(g.rules) for name, g in self._groups.items()}

    async def list_groups(self) -> dict[str, list[AccessRule]]:
        """Return rules grouped by file."""
        return self.groups

    async def get(self, rule_id: str) -> tuple[str, AccessRule] | None:
        """Find a rule by ID. Returns (group_name, rule) or None."""
        for name, group in self._groups.items():
            for rule in group.rules:
                if rule.id == rule_id:
                    return (name, rule)
        return None

    async def create(self, rule: AccessRule, group: str = "default") -> None:
        """Create a rule in the specified group file."""
        # Check for duplicates across all groups
        all_rules = self.rules
        for existing in all_rules:
            if existing.id == rule.id:
                raise ValueError(f"Access rule '{rule.id}' already exists")
            if existing.domain.lower() == rule.domain.lower():
                raise ValueError(
                    f"Access rule for domain '{rule.domain}' already exists (id: '{existing.id}')"
                )

        # Create group if it doesn't exist
        if group not in self._groups:
            path = self._resolve_group_path(group)
            self._groups[group] = AccessRuleGroup(group, path, [])

        self._groups[group].rules.append(rule)
        self._save_group(group)

    async def update(self, rule_id: str, rule: AccessRule) -> None:
        """Update a rule in its current group file."""
        for name, grp in self._groups.items():
            for i, existing in enumerate(grp.rules):
                if existing.id == rule_id:
                    grp.rules[i] = rule
                    self._save_group(name)
                    return
        raise KeyError(f"Access rule '{rule_id}' not found")

    async def delete(self, rule_id: str) -> None:
        """Delete a rule from its group file."""
        for name, grp in self._groups.items():
            for i, existing in enumerate(grp.rules):
                if existing.id == rule_id:
                    grp.rules.pop(i)
                    if grp.rules:
                        self._save_group(name)
                    else:
                        # Group is now empty — remove file and group
                        try:
                            grp.path.unlink()
                        except OSError:
                            pass
                        del self._groups[name]
                    return
        raise KeyError(f"Access rule '{rule_id}' not found")

    async def watch(self, callback: Callable[[list[AccessRule]], None]) -> None:
        """Watch both access-rules.yaml and access-rules.d/ for changes."""
        from watchfiles import awatch

        watch_paths: list[str | Path] = []
        if self._main_file.exists():
            watch_paths.append(self._main_file)
        if self._drop_in_dir.is_dir():
            watch_paths.append(self._drop_in_dir)
        if not watch_paths:
            self._drop_in_dir.mkdir(parents=True, exist_ok=True)
            watch_paths.append(self._drop_in_dir)

        logger.info("Watching access rules at %s", watch_paths)
        async for _changes in awatch(*watch_paths):
            logger.info("Detected access rules change, reloading")
            old_groups = dict(self._groups)
            old_rules = self.rules
            try:
                self._load()
            except ValueError:
                logger.exception("Invalid access rules after change, keeping previous")
                self._groups = old_groups
                continue
            if self.rules != old_rules:
                try:
                    callback(self.rules)
                except Exception:
                    logger.exception("Error in access rules watch callback")

    def reload(self) -> list[AccessRule]:
        """Manually trigger a reload. Preserves previous state on error."""
        old_groups = dict(self._groups)
        try:
            return self._load()
        except Exception:
            logger.exception("Reload failed, keeping previous access rules")
            self._groups = old_groups
            return self.rules

    async def start_watching(
        self, callback: Callable[[list[AccessRule]], None]
    ) -> asyncio.Task[None]:
        task = asyncio.create_task(self.watch(callback))
        return task
