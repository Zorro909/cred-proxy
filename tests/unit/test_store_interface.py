"""AC-16: Storage interface contract tests."""

import pytest

from auth_injection_proxy.matching.models import BearerAuth, CredentialRule
from tests.conftest import MockCredentialStore


def _make_rule(rule_id: str = "r1") -> CredentialRule:
    return CredentialRule(
        id=rule_id,
        domain="example.com",
        enabled=True,
        auth=BearerAuth(type="bearer", token="tok"),
    )


class TestCredentialStoreContract:
    """AC-16.1: Verify the interface contract with MockCredentialStore."""

    async def test_list_empty(self):
        store = MockCredentialStore()
        assert await store.list() == []

    async def test_create_and_list(self):
        store = MockCredentialStore()
        rule = _make_rule()
        await store.create(rule)
        result = await store.list()
        assert len(result) == 1
        assert result[0].id == "r1"

    async def test_get_existing(self):
        store = MockCredentialStore([_make_rule()])
        result = await store.get("r1")
        assert result is not None
        assert result.id == "r1"

    async def test_get_missing(self):
        store = MockCredentialStore()
        assert await store.get("missing") is None

    async def test_create_duplicate_raises(self):
        store = MockCredentialStore([_make_rule()])
        with pytest.raises(ValueError, match="Duplicate"):
            await store.create(_make_rule())

    async def test_update(self):
        store = MockCredentialStore([_make_rule()])
        updated = _make_rule()
        updated = CredentialRule(
            id="r1",
            domain="new.example.com",
            enabled=True,
            auth=BearerAuth(type="bearer", token="new-tok"),
        )
        await store.update("r1", updated)
        result = await store.get("r1")
        assert result is not None
        assert result.domain == "new.example.com"

    async def test_update_missing_raises(self):
        store = MockCredentialStore()
        with pytest.raises(KeyError):
            await store.update("missing", _make_rule())

    async def test_delete(self):
        store = MockCredentialStore([_make_rule()])
        await store.delete("r1")
        assert await store.get("r1") is None

    async def test_delete_missing_raises(self):
        store = MockCredentialStore()
        with pytest.raises(KeyError):
            await store.delete("missing")

    async def test_mock_works_transparently(self):
        """AC-5.6: Mock implementation works transparently."""
        store = MockCredentialStore()
        rule = _make_rule("x1")
        await store.create(rule)
        fetched = await store.get("x1")
        assert fetched == rule
        await store.delete("x1")
        assert await store.list() == []
