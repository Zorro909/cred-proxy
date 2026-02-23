"""Pydantic v2 models for credential rules and auth configurations."""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field


class BearerAuth(BaseModel):
    type: Literal["bearer"]
    token: str


class BasicAuth(BaseModel):
    type: Literal["basic"]
    username: str
    password: str


class HeaderAuth(BaseModel):
    type: Literal["header"]
    header_name: str
    header_value: str


class QueryParamAuth(BaseModel):
    type: Literal["query_param"]
    param_name: str
    param_value: str


class OAuth2ClientCredentialsAuth(BaseModel):
    type: Literal["oauth2_client_credentials"]
    token_url: str
    client_id: str
    client_secret: str
    scopes: list[str] = Field(default_factory=list)


AuthConfig = Annotated[
    Union[  # noqa: UP007 — required for Pydantic discriminator
        BearerAuth,
        BasicAuth,
        HeaderAuth,
        QueryParamAuth,
        OAuth2ClientCredentialsAuth,
    ],
    Field(discriminator="type"),
]


class CredentialRule(BaseModel):
    id: str
    domain: str
    path_prefix: str | None = None
    enabled: bool = True
    auth: AuthConfig
