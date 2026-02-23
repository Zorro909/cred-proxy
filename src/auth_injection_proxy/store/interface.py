"""Abstract CredentialStore interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from auth_injection_proxy.matching.models import CredentialRule

RuleList = list[CredentialRule]


class CredentialStore(ABC):
    @abstractmethod
    async def list(self) -> RuleList: ...

    @abstractmethod
    async def get(self, rule_id: str) -> CredentialRule | None: ...

    @abstractmethod
    async def create(self, rule: CredentialRule) -> None: ...

    @abstractmethod
    async def update(self, rule_id: str, rule: CredentialRule) -> None: ...

    @abstractmethod
    async def delete(self, rule_id: str) -> None: ...

    @abstractmethod
    async def watch(self, callback: Callable[[RuleList], None]) -> None:
        """Start watching for external changes. Calls callback with new rules list."""
        ...
