"""Management API — /api/status route."""

from __future__ import annotations

import time

from fastapi import APIRouter

from auth_injection_proxy.access.store import AccessRuleStore
from auth_injection_proxy.store.interface import CredentialStore

_start_time: float = time.monotonic()


def create_status_router(
    store: CredentialStore,
    access_store: AccessRuleStore | None = None,
) -> APIRouter:
    router = APIRouter(tags=["status"])

    @router.get("/api/status")
    async def get_status() -> dict:
        rules = await store.list()
        enabled_count = sum(1 for r in rules if r.enabled)
        result: dict = {
            "status": "ok",
            "uptime_seconds": round(time.monotonic() - _start_time, 1),
            "total_rules": len(rules),
            "enabled_rules": enabled_count,
        }
        if access_store is not None:
            access_groups = await access_store.list()
            total_access = sum(len(r) for r in access_groups.values())
            result["total_access_rules"] = total_access
            result["access_rule_groups"] = len(access_groups)
        return result

    return router
