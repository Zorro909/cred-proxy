"""Management API — /api/status route."""

from __future__ import annotations

import time

from fastapi import APIRouter

from auth_injection_proxy.store.interface import CredentialStore

_start_time: float = time.monotonic()


def create_status_router(store: CredentialStore) -> APIRouter:
    router = APIRouter(tags=["status"])

    @router.get("/api/status")
    async def get_status() -> dict:
        rules = await store.list()
        enabled_count = sum(1 for r in rules if r.enabled)
        return {
            "status": "ok",
            "uptime_seconds": round(time.monotonic() - _start_time, 1),
            "total_rules": len(rules),
            "enabled_rules": enabled_count,
        }

    return router
