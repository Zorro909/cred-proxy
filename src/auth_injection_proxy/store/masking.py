"""Secret value masking utilities (AC-7.1–7.5)."""

from __future__ import annotations

from auth_injection_proxy.matching.models import (
    BasicAuth,
    BearerAuth,
    CredentialRule,
    ExternalScriptAuth,
    HeaderAuth,
    OAuth2ClientCredentialsAuth,
    QueryParamAuth,
)


def mask_secret(value: str, visible_suffix: int = 3) -> str:
    """Mask a secret, keeping last `visible_suffix` chars visible.

    E.g. "sk-proj-abc123xyz789" -> "sk-***789"
    """
    if len(value) <= visible_suffix:
        return "***"
    # Find a prefix before the first dash/special char or use first 2 chars
    prefix = ""
    for i, ch in enumerate(value):
        if ch in "-_." and i > 0:
            prefix = value[: i + 1]
            break
    if not prefix:
        prefix = ""
    return f"{prefix}***{value[-visible_suffix:]}"


def mask_rule(rule: CredentialRule) -> dict:
    """Return a dict representation of a rule with secrets masked."""
    data = rule.model_dump()
    auth = rule.auth

    match auth:
        case BearerAuth():
            data["auth"]["token"] = mask_secret(auth.token)
        case BasicAuth():
            # AC-7.2: username shown, password masked
            data["auth"]["password"] = "***"
        case HeaderAuth():
            data["auth"]["header_value"] = mask_secret(auth.header_value)
        case QueryParamAuth():
            data["auth"]["param_value"] = mask_secret(auth.param_value)
        case OAuth2ClientCredentialsAuth():
            # AC-7.4: client_id and token_url shown, client_secret masked
            data["auth"]["client_secret"] = mask_secret(auth.client_secret)
        case ExternalScriptAuth():
            data["auth"]["env"] = {k: "***" for k in auth.env}

    return data
