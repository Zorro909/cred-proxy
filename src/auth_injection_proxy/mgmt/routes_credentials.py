"""Management API — CRUD routes for /api/credentials."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ValidationError

from auth_injection_proxy.matching.models import AuthConfig, CredentialRule
from auth_injection_proxy.store.interface import CredentialStore
from auth_injection_proxy.store.masking import mask_rule


class CredentialCreateRequest(BaseModel):
    id: str
    domain: str
    path_prefix: str | None = None
    enabled: bool = True
    auth: AuthConfig


class CredentialUpdateRequest(BaseModel):
    domain: str | None = None
    path_prefix: str | None = None
    enabled: bool | None = None
    auth: AuthConfig | None = None


def create_credentials_router(store: CredentialStore) -> APIRouter:
    router = APIRouter(prefix="/api/credentials", tags=["credentials"])

    @router.get("")
    async def list_credentials() -> list[dict]:
        rules = await store.list()
        return [mask_rule(r) for r in rules]

    @router.post("", status_code=201)
    async def create_credential(body: CredentialCreateRequest) -> dict:
        try:
            rule = CredentialRule.model_validate(body.model_dump())
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        try:
            await store.create(rule)
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        return mask_rule(rule)

    @router.put("/{rule_id}")
    async def update_credential(rule_id: str, body: CredentialUpdateRequest) -> dict:
        existing = await store.get(rule_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Credential '{rule_id}' not found")

        update_data = body.model_dump(exclude_none=True)
        merged = existing.model_dump()
        merged.update(update_data)
        merged["id"] = rule_id  # ID cannot change
        updated_rule = CredentialRule.model_validate(merged)
        await store.update(rule_id, updated_rule)
        return mask_rule(updated_rule)

    @router.delete("/{rule_id}", status_code=204)
    async def delete_credential(rule_id: str) -> None:
        existing = await store.get(rule_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Credential '{rule_id}' not found")
        await store.delete(rule_id)

    @router.post("/{rule_id}/test")
    async def test_credential(rule_id: str) -> dict:
        existing = await store.get(rule_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Credential '{rule_id}' not found")
        # Test by making a simple HEAD/GET request to the domain
        import httpx

        url = f"https://{existing.domain}/"
        if existing.path_prefix:
            url = f"https://{existing.domain}{existing.path_prefix}"
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=10) as client:
                resp = await client.head(url)
                return {"status_code": resp.status_code, "success": resp.status_code < 400}
        except httpx.HTTPError as e:
            return {"status_code": 0, "success": False, "error": str(e)}

    return router
