"""Management API — /setup/{token} routes for credential setup flow."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from auth_injection_proxy.matching.models import (
    BasicAuth,
    BearerAuth,
    CredentialRule,
    HeaderAuth,
    OAuth2ClientCredentialsAuth,
    QueryParamAuth,
)
from auth_injection_proxy.requests.pending import PendingRequestStore, RequestStatus
from auth_injection_proxy.store.interface import CredentialStore

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"
_jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)


def create_setup_router(store: CredentialStore, pending: PendingRequestStore) -> APIRouter:
    router = APIRouter(tags=["setup"])

    @router.get("/setup/{token}", response_class=HTMLResponse)
    async def get_setup_page(token: str) -> HTMLResponse:
        req = pending.get(token)
        if req is None:
            raise HTTPException(status_code=404, detail="Unknown setup token")
        if req.status != RequestStatus.PENDING:
            raise HTTPException(status_code=410, detail="Setup link has expired or been used")

        template = _jinja_env.get_template("setup.html")
        html = template.render(
            token=token,
            domain=req.domain,
            reason=req.reason,
            auth_type=req.auth_type or "",
        )
        return HTMLResponse(content=html)

    @router.post("/setup/{token}", response_class=HTMLResponse)
    async def submit_setup(
        token: str,
        request: Request,
    ) -> HTMLResponse:
        req = pending.get(token)
        if req is None:
            raise HTTPException(status_code=404, detail="Unknown setup token")
        if req.status != RequestStatus.PENDING:
            raise HTTPException(status_code=410, detail="Setup link has expired or been used")

        form = await request.form()
        auth_type = str(form.get("auth_type", ""))

        try:
            auth_config = _build_auth_config(auth_type, form)
        except ValueError as e:
            template = _jinja_env.get_template("setup.html")
            html = template.render(
                token=token,
                domain=req.domain,
                reason=req.reason,
                auth_type=auth_type,
                error=str(e),
            )
            return HTMLResponse(content=html, status_code=400)

        # Generate an ID from the domain
        rule_id = req.domain.replace(".", "-").replace("*", "wildcard")
        # Ensure unique
        existing = await store.get(rule_id)
        counter = 1
        base_id = rule_id
        while existing is not None:
            rule_id = f"{base_id}-{counter}"
            existing = await store.get(rule_id)
            counter += 1

        rule = CredentialRule(
            id=rule_id,
            domain=req.domain,
            enabled=True,
            auth=auth_config,
        )
        await store.create(rule)
        pending.fulfill(token, rule_id)

        logger.info("Setup completed: token=%s rule_id=%s", token[:8] + "...", rule_id)

        return HTMLResponse(
            content=f"<html><body><h1>Credential configured</h1>"
            f"<p>Credential <strong>{rule_id}</strong> has been created for "
            f"<strong>{req.domain}</strong>.</p></body></html>"
        )

    return router


def _build_auth_config(
    auth_type: str,
    form: Any,
) -> BearerAuth | BasicAuth | HeaderAuth | QueryParamAuth | OAuth2ClientCredentialsAuth:
    """Build an AuthConfig from form data. Raises ValueError on validation failure."""
    match auth_type:
        case "bearer":
            token = str(form.get("token", "")).strip()  # type: ignore[union-attr]
            if not token:
                raise ValueError("Token is required")
            return BearerAuth(type="bearer", token=token)
        case "basic":
            username = str(form.get("username", "")).strip()  # type: ignore[union-attr]
            password = str(form.get("password", "")).strip()  # type: ignore[union-attr]
            if not username or not password:
                raise ValueError("Username and password are required")
            return BasicAuth(type="basic", username=username, password=password)
        case "header":
            name = str(form.get("header_name", "")).strip()  # type: ignore[union-attr]
            value = str(form.get("header_value", "")).strip()  # type: ignore[union-attr]
            if not name or not value:
                raise ValueError("Header name and value are required")
            return HeaderAuth(type="header", header_name=name, header_value=value)
        case "query_param":
            name = str(form.get("param_name", "")).strip()  # type: ignore[union-attr]
            value = str(form.get("param_value", "")).strip()  # type: ignore[union-attr]
            if not name or not value:
                raise ValueError("Parameter name and value are required")
            return QueryParamAuth(type="query_param", param_name=name, param_value=value)
        case "oauth2_client_credentials":
            token_url = str(form.get("token_url", "")).strip()  # type: ignore[union-attr]
            client_id = str(form.get("client_id", "")).strip()  # type: ignore[union-attr]
            client_secret = str(form.get("client_secret", "")).strip()  # type: ignore[union-attr]
            scopes_raw = str(form.get("scopes", "")).strip()  # type: ignore[union-attr]
            if not token_url or not client_id or not client_secret:
                raise ValueError("Token URL, client ID, and client secret are required")
            scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()] if scopes_raw else []
            return OAuth2ClientCredentialsAuth(
                type="oauth2_client_credentials",
                token_url=token_url,
                client_id=client_id,
                client_secret=client_secret,
                scopes=scopes,
            )
        case _:
            raise ValueError("Please select an auth type")
