"""FastAPI application factory for the management API."""

from __future__ import annotations

from fastapi import FastAPI

from auth_injection_proxy.access.store import AccessRuleStore
from auth_injection_proxy.mgmt.routes_access_rules import create_access_rules_router
from auth_injection_proxy.mgmt.routes_credentials import create_credentials_router
from auth_injection_proxy.mgmt.routes_setup import create_setup_router
from auth_injection_proxy.mgmt.routes_status import create_status_router
from auth_injection_proxy.requests.pending import PendingRequestStore
from auth_injection_proxy.store.interface import CredentialStore


def create_app(
    store: CredentialStore,
    pending: PendingRequestStore,
    access_store: AccessRuleStore | None = None,
) -> FastAPI:
    """Create the FastAPI management application."""
    app = FastAPI(title="Auth Injection Proxy Management API", version="0.1.0")

    app.include_router(create_credentials_router(store))
    if access_store is not None:
        app.include_router(create_access_rules_router(access_store))
    app.include_router(create_setup_router(store, pending))
    app.include_router(create_status_router(store, access_store))

    return app
