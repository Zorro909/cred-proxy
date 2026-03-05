"""Dispatcher: selects injection strategy per auth type."""

from __future__ import annotations

from mitmproxy import http

from auth_injection_proxy.injection.basic import inject_basic
from auth_injection_proxy.injection.bearer import inject_bearer
from auth_injection_proxy.injection.external_script import ExternalScriptManager
from auth_injection_proxy.injection.header import inject_header
from auth_injection_proxy.injection.oauth2 import OAuth2TokenManager
from auth_injection_proxy.injection.query_param import inject_query_param
from auth_injection_proxy.matching.models import (
    BasicAuth,
    BearerAuth,
    CredentialRule,
    ExternalScriptAuth,
    HeaderAuth,
    OAuth2ClientCredentialsAuth,
    QueryParamAuth,
)


async def inject_auth(
    flow: http.HTTPFlow,
    rule: CredentialRule,
    oauth2_manager: OAuth2TokenManager,
    external_script_manager: ExternalScriptManager,
    config_dir: str,
) -> list[str]:
    """Inject auth into the flow based on rule type. Returns injected secret values."""
    match rule.auth:
        case BearerAuth(token=token):
            return inject_bearer(flow, token)
        case BasicAuth(username=username, password=password):
            return inject_basic(flow, username, password)
        case HeaderAuth(header_name=name, header_value=value):
            return inject_header(flow, name, value)
        case QueryParamAuth(param_name=name, param_value=value):
            return inject_query_param(flow, name, value)
        case OAuth2ClientCredentialsAuth(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
        ):
            return await oauth2_manager.inject(
                flow, rule.id, token_url, client_id, client_secret, scopes
            )
        case ExternalScriptAuth(script=script, env=env, refresh_interval=interval):
            return await external_script_manager.inject(
                flow, rule.id, script, env, interval, config_dir
            )
    return []
