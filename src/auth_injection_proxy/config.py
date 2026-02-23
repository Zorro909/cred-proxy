"""YAML config loading and validation."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator

from auth_injection_proxy.matching.models import CredentialRule


class ProxyConfig(BaseModel):
    listen_port: int = 8080
    mgmt_port: int = 8081
    credential_request_ttl: int = 900


class AppConfig(BaseModel):
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    credentials: list[CredentialRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_ids(self) -> AppConfig:
        ids = [r.id for r in self.credentials]
        dupes = [x for x in ids if ids.count(x) > 1]
        if dupes:
            raise ValueError(f"Duplicate credential IDs: {set(dupes)}")
        return self


def load_config(path: str | Path) -> AppConfig:
    """Load and validate config from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    text = path.read_text()
    data = yaml.safe_load(text)
    if data is None:
        data = {}
    return AppConfig.model_validate(data)
