"""Management API — CRUD routes for /api/access-rules."""

from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ValidationError, field_validator

from auth_injection_proxy.access.models import AccessRule
from auth_injection_proxy.access.store import AccessRuleStore

VALID_GROUP_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


class AccessRuleCreateRequest(BaseModel):
    id: str
    domain: str
    mode: Literal["allow", "deny"]
    paths: list[str] = []
    group: str = "default"

    @field_validator("paths")
    @classmethod
    def validate_regex_patterns(cls, v: list[str]) -> list[str]:
        for i, pattern in enumerate(v):
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(
                    f"Invalid regex at paths[{i}] ({pattern!r}): {e}"
                ) from e
        return v


class AccessRuleUpdateRequest(BaseModel):
    domain: str | None = None
    mode: Literal["allow", "deny"] | None = None
    paths: list[str] | None = None

    @field_validator("paths")
    @classmethod
    def validate_regex_patterns(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for i, pattern in enumerate(v):
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(
                    f"Invalid regex at paths[{i}] ({pattern!r}): {e}"
                ) from e
        return v


def create_access_rules_router(access_store: AccessRuleStore) -> APIRouter:
    router = APIRouter(prefix="/api/access-rules", tags=["access-rules"])

    @router.get("")
    async def list_access_rules() -> dict:
        groups = await access_store.list()
        return {
            "groups": {
                name: [r.model_dump() for r in rules]
                for name, rules in groups.items()
            }
        }

    @router.get("/{rule_id}")
    async def get_access_rule(rule_id: str) -> dict:
        result = await access_store.get(rule_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Access rule '{rule_id}' not found")
        group_name, rule = result
        return {"group": group_name, "rule": rule.model_dump()}

    @router.post("", status_code=201)
    async def create_access_rule(body: AccessRuleCreateRequest) -> dict:
        # Validate group name
        if not VALID_GROUP_RE.match(body.group):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid group name '{body.group}': must be alphanumeric, hyphens, "
                "underscores",
            )

        try:
            rule = AccessRule.model_validate({
                "id": body.id,
                "domain": body.domain,
                "mode": body.mode,
                "paths": body.paths,
            })
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

        try:
            await access_store.create(rule, group=body.group)
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e

        return rule.model_dump()

    @router.put("/{rule_id}")
    async def update_access_rule(rule_id: str, body: AccessRuleUpdateRequest) -> dict:
        result = await access_store.get(rule_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Access rule '{rule_id}' not found")

        group_name, existing = result
        update_data = body.model_dump(exclude_none=True)
        merged = existing.model_dump()
        merged.update(update_data)
        merged["id"] = rule_id  # ID cannot change

        try:
            updated_rule = AccessRule.model_validate(merged)
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

        await access_store.update(rule_id, updated_rule)
        return updated_rule.model_dump()

    @router.delete("/{rule_id}", status_code=204)
    async def delete_access_rule(rule_id: str) -> None:
        result = await access_store.get(rule_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Access rule '{rule_id}' not found")
        await access_store.delete(rule_id)

    return router
