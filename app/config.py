from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SECPA_",
        extra="ignore",
    )

    app_name: str = "Azure Security Posture Agent"
    app_version: str = "1.0.0"
    build_id: str = "dev"
    log_level: str = "INFO"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    session_cookie_name: str = "secpa_session"
    session_cookie_secure: bool = False
    session_max_age_seconds: int = 3600
    allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["http://localhost:8000"])
    artifact_dir: Path = Path("artifacts")
    m365_dist_dir: Path = Path("m365-agent/dist")
    browser_redirect_path: str = "/api/auth/browser/callback"
    entra_redirect_uri: str = "http://localhost:8000/api/auth/browser/callback"
    browser_redirect_allowlist: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:8000/api/auth/browser/callback"]
    )
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_authority: str = "https://login.microsoftonline.com/common"
    management_resource: str = "https://management.azure.com/"
    delegated_scope: str = "https://management.azure.com/user_impersonation"
    default_subscription_id: str = ""
    default_tenant_id: str = ""
    user_agent: str = "azure-security-posture-agent/1.0"
    container_app_name: str = "azure-security-posture-agent"
    container_env_name: str = "sec-posture-env"
    resource_group_name: str = "rg-azure-security-posture-agent"
    acr_repository_name: str = "azure-security-posture-agent"
    optional_graph_enabled: bool = False
    enable_graph_enrichment: bool = False
    enable_defender: bool = True
    enable_policy: bool = True
    enable_resource_graph: bool = True
    strict_validation_default: bool = True
    copilot_audience: str = "api://azure-security-posture-agent"
    graph_resource: str = "https://graph.microsoft.com/"
    tenant_discovery_api_version: str = "2022-12-01"
    subscription_api_version: str = "2020-01-01"

    @field_validator("allowed_origins", "browser_redirect_allowlist", mode="before")
    @classmethod
    def parse_url_list(cls, value: object) -> object:
        if not isinstance(value, str):
            return value

        raw_value = value.strip()
        try:
            parsed = json.loads(raw_value)
        except json.JSONDecodeError:
            inner_value = raw_value[1:-1] if raw_value.startswith("[") and raw_value.endswith("]") else raw_value
            return [item.strip().strip('"\'') for item in inner_value.split(",") if item.strip()]

        return parsed

    @property
    def exports_dir(self) -> Path:
        return self.artifact_dir


settings = Settings()
