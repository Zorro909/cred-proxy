"""AC-5, AC-16.2: YAML backend tests."""

import pytest

from auth_injection_proxy.matching.models import BearerAuth, CredentialRule
from auth_injection_proxy.store.yaml_store import YamlCredentialStore


def _write_yaml(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


class TestYamlStore:
    def test_load_valid_yaml(self, sample_yaml):
        """AC-5.1: Parses all auth types from YAML."""
        store = YamlCredentialStore(sample_yaml)
        assert len(store._rules) == 2
        assert store._rules[0].id == "openai-prod"
        assert store._rules[1].id == "github-api"

    def test_load_empty_file(self, tmp_path):
        path = tmp_path / "empty.yaml"
        path.write_text("credentials: []\n")
        store = YamlCredentialStore(str(path))
        assert store._rules == []

    def test_load_missing_file(self, tmp_path):
        store = YamlCredentialStore(str(tmp_path / "missing.yaml"))
        assert store._rules == []

    async def test_create_writes_file(self, tmp_path):
        path = tmp_path / "store.yaml"
        path.write_text("credentials: []\n")
        store = YamlCredentialStore(str(path))
        rule = CredentialRule(
            id="new",
            domain="example.com",
            enabled=True,
            auth=BearerAuth(type="bearer", token="tok"),
        )
        await store.create(rule)
        assert len(store._rules) == 1
        # Verify persisted
        store2 = YamlCredentialStore(str(path))
        assert len(store2._rules) == 1
        assert store2._rules[0].id == "new"

    async def test_create_duplicate_raises(self, sample_yaml):
        store = YamlCredentialStore(sample_yaml)
        dupe = CredentialRule(
            id="openai-prod",
            domain="other.com",
            auth=BearerAuth(type="bearer", token="t"),
        )
        with pytest.raises(ValueError, match="already exists"):
            await store.create(dupe)

    async def test_update(self, sample_yaml):
        store = YamlCredentialStore(sample_yaml)
        updated = CredentialRule(
            id="openai-prod",
            domain="api.openai.com",
            path_prefix="/v2/",
            auth=BearerAuth(type="bearer", token="new-tok"),
        )
        await store.update("openai-prod", updated)
        result = await store.get("openai-prod")
        assert result is not None
        assert result.path_prefix == "/v2/"

    async def test_update_missing_raises(self, sample_yaml):
        store = YamlCredentialStore(sample_yaml)
        rule = CredentialRule(id="x", domain="x.com", auth=BearerAuth(type="bearer", token="t"))
        with pytest.raises(KeyError):
            await store.update("nonexistent", rule)

    async def test_delete(self, sample_yaml):
        store = YamlCredentialStore(sample_yaml)
        await store.delete("openai-prod")
        assert await store.get("openai-prod") is None

    async def test_delete_missing_raises(self, sample_yaml):
        store = YamlCredentialStore(sample_yaml)
        with pytest.raises(KeyError):
            await store.delete("nonexistent")

    def test_reload_invalid_yaml_keeps_previous(self, tmp_path):
        """AC-5.5: Invalid YAML keeps previous rules."""
        path = tmp_path / "creds.yaml"
        path.write_text(
            "credentials:\n  - id: r1\n    domain: x.com\n    auth:\n"
            "      type: bearer\n      token: t\n"
        )
        store = YamlCredentialStore(str(path))
        assert len(store._rules) == 1

        # Write invalid YAML
        path.write_text("credentials: [invalid yaml {{{")
        store.reload()
        # Previous rules preserved
        assert len(store._rules) == 1

    def test_atomic_write(self, tmp_path):
        """Atomic write uses os.replace so partial writes don't corrupt."""
        path = tmp_path / "store.yaml"
        path.write_text("credentials: []\n")
        store = YamlCredentialStore(str(path))
        # After save, no .tmp files should remain
        import asyncio

        asyncio.run(
            store.create(
                CredentialRule(id="r1", domain="x.com", auth=BearerAuth(type="bearer", token="t"))
            )
        )
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert len(tmp_files) == 0
