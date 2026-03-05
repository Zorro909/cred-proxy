"""Pydantic v2 models for access rules."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AccessRule(BaseModel):
    id: str
    domain: str
    mode: Literal["allow", "deny"]
    paths: list[str] = Field(default_factory=list)

    # Compiled patterns — excluded from serialization
    _compiled: list[re.Pattern[str]] = []

    @field_validator("paths")
    @classmethod
    def validate_regex_patterns(cls, v: list[str]) -> list[str]:
        """Validate that all path strings are valid regex."""
        for i, pattern in enumerate(v):
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(
                    f"Invalid regex at paths[{i}] ({pattern!r}): {e}"
                ) from e
        return v

    def model_post_init(self, __context: object) -> None:
        """Compile regex patterns on construction for runtime performance."""
        object.__setattr__(
            self,
            "_compiled",
            [re.compile(p) for p in self.paths],
        )

    def path_matches(self, path: str) -> bool:
        """Return True if the path matches any of the compiled patterns."""
        return any(r.search(path) for r in self._compiled)

    def is_allowed(self, path: str) -> bool:
        """Return True if a request to this path should be permitted."""
        matched = self.path_matches(path)
        if self.mode == "allow":
            return matched  # allowlist: must match to pass
        else:
            return not matched  # denylist: must NOT match to pass
