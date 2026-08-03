from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from shutil import which
from urllib.parse import urlparse
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import HTTPException, status
from jwt import PyJWKClient

from app.auth import decode_jwt_payload_unsafe, validate_tenant_claim
from app.config import settings
from app.models import AuthMode, SessionPrincipal


ARM_RESOURCE = settings.management_resource
OIDC_CACHE: dict[str, dict[str, str]] = {}
JWKS_CLIENT_CACHE: dict[str, PyJWKClient] = {}


def _resolve_az_command() -> str:
    az_cmd = which("az") or which("az.cmd")
    if az_cmd:
        return az_cmd

    fallback = Path("C:/Program Files/Microsoft SDKs/Azure/CLI2/wbin/az.cmd")
    if fallback.exists():
        return str(fallback)

    raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Azure CLI not found.")


def _wrap_az_command(az_cmd: str, args: list[str]) -> list[str]:
    command = [az_cmd, *args]
    if az_cmd.lower().endswith(".cmd"):
        return ["cmd", "/c", *command]
    return command


def _parse_expires_on(raw_value: str | int | None) -> datetime:
    if raw_value is None:
        return datetime.now(UTC)
    if isinstance(raw_value, int):
        return datetime.fromtimestamp(raw_value, UTC)
    try:
        timestamp = int(raw_value)
        return datetime.fromtimestamp(timestamp, UTC)
    except ValueError:
        if raw_value.isdigit():
            return datetime.now(UTC)
        if raw_value.endswith("Z"):
            return datetime.fromisoformat(raw_value.replace("Z", "+00:00")).astimezone(UTC)
        if "T" not in raw_value:
            return datetime.now(UTC)
        return datetime.fromisoformat(raw_value.replace("Z", "+00:00")).astimezone(UTC)


async def fetch_openid_configuration(tenant_id: str) -> dict[str, str]:
    cache_key = tenant_id
    if cache_key in OIDC_CACHE:
        return OIDC_CACHE[cache_key]
    authority_root = settings.entra_authority.rstrip("/")
    base = authority_root.rsplit("/", 1)[0] if authority_root.endswith("/common") else authority_root
    url = f"{base}/{tenant_id}/v2.0/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=30.0, headers={"User-Agent": settings.user_agent}) as client:
        response = await client.get(url)
    if response.status_code >= 400:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Unable to load OpenID configuration.")
    payload = response.json()
    OIDC_CACHE[cache_key] = payload
    return payload


async def validate_jwt_token(token: str, tenant_id: str, audience: str) -> dict[str, str | int]:
    unverified_claims = decode_jwt_payload_unsafe(token)
    token_tenant_id = str(unverified_claims.get("tid") or tenant_id)
    if token_tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token tenant does not match the selected tenant.")
    configuration = await fetch_openid_configuration(tenant_id)
    jwks_uri = configuration["jwks_uri"]
    jwks_client = JWKS_CLIENT_CACHE.setdefault(jwks_uri, PyJWKClient(jwks_uri))
    signing_key = jwks_client.get_signing_key_from_jwt(token).key
    issuer = configuration["issuer"]
    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Bearer token validation failed: {exc}") from exc
    validate_tenant_claim(tenant_id, claims)
    return claims


def build_authorization_url(tenant_id: str, redirect_uri: str, state: str, challenge: str) -> str:
    authority = settings.entra_authority.rstrip("/")
    if authority.endswith("/common"):
        authority = authority[:-7]
    tenant_authority = f"{authority}/{tenant_id}/oauth2/v2.0/authorize"
    query = urlencode(
        {
            "client_id": settings.entra_client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": f"openid profile offline_access {settings.delegated_scope}",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{tenant_authority}?{query}"


async def exchange_browser_code(code: str, tenant_id: str, redirect_uri: str, verifier: str) -> SessionPrincipal:
    token_url = f"{settings.entra_authority.rstrip('/').rsplit('/', 1)[0]}/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": settings.entra_client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
        "scope": f"openid profile offline_access {settings.delegated_scope}",
    }
    if settings.entra_client_secret:
        data["client_secret"] = settings.entra_client_secret

    async with httpx.AsyncClient(timeout=60.0, headers={"User-Agent": settings.user_agent}) as client:
        response = await client.post(token_url, data=data)

    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Browser token exchange failed: {response.text}",
        )

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Browser exchange did not return an access token.")

    claims = await validate_jwt_token(access_token, tenant_id, ARM_RESOURCE)
    return SessionPrincipal(
        auth_mode=AuthMode.browser,
        tenant_id=tenant_id,
        access_token=access_token,
        expires_on_utc=_parse_expires_on(payload.get("expires_on") or claims.get("exp")),
        user_object_id=claims.get("oid"),
        username=claims.get("preferred_username") or claims.get("upn"),
        audience=claims.get("aud"),
        issuer=claims.get("iss"),
        token_claims=claims,
    )


def acquire_cli_principal(tenant_id: str) -> SessionPrincipal:
    az_cmd = _resolve_az_command()
    command = _wrap_az_command(
        az_cmd,
        [
            "account",
            "get-access-token",
            "--resource",
            ARM_RESOURCE,
            "--tenant",
            tenant_id,
            "--output",
            "json",
        ],
    )
    process = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if process.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Azure CLI token acquisition failed: {process.stderr.strip()}",
        )

    payload = json.loads(process.stdout)
    access_token = payload.get("accessToken")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Azure CLI did not return an access token.")

    claims = decode_jwt_payload_unsafe(access_token)
    validate_tenant_claim(tenant_id, claims)
    return SessionPrincipal(
        auth_mode=AuthMode.cli,
        tenant_id=tenant_id,
        access_token=access_token,
        expires_on_utc=_parse_expires_on(payload.get("expiresOn") or claims.get("exp")),
        user_object_id=claims.get("oid"),
        username=claims.get("preferred_username") or claims.get("upn"),
        audience=claims.get("aud"),
        issuer=claims.get("iss"),
        token_claims=claims,
    )


async def acquire_copilot_principal(tenant_id: str, bearer_token: str) -> SessionPrincipal:
    claims = await validate_jwt_token(bearer_token, tenant_id, settings.copilot_audience)
    if not settings.entra_client_id or not settings.entra_client_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Hosted delegated collection requires server-side OBO credentials configured outside source control.",
        )

    token_url = f"{settings.entra_authority.rstrip('/').rsplit('/', 1)[0]}/{tenant_id}/oauth2/v2.0/token"
    obo_data = {
        "client_id": settings.entra_client_id,
        "client_secret": settings.entra_client_secret,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": bearer_token,
        "requested_token_use": "on_behalf_of",
        "scope": settings.delegated_scope,
    }
    async with httpx.AsyncClient(timeout=60.0, headers={"User-Agent": settings.user_agent}) as client:
        obo_response = await client.post(token_url, data=obo_data)
    if obo_response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="On-behalf-of token acquisition for Azure Resource Manager failed.",
        )
    obo_payload = obo_response.json()
    arm_token = obo_payload.get("access_token")
    if not arm_token:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="OBO exchange did not return an ARM token.")
    arm_claims = decode_jwt_payload_unsafe(arm_token)
    validate_tenant_claim(tenant_id, arm_claims)

    return SessionPrincipal(
        auth_mode=AuthMode.delegated,
        tenant_id=tenant_id,
        access_token=arm_token,
        expires_on_utc=_parse_expires_on(obo_payload.get("expires_on") or arm_claims.get("exp")),
        user_object_id=claims.get("oid"),
        username=claims.get("preferred_username") or claims.get("upn"),
        audience=arm_claims.get("aud"),
        issuer=arm_claims.get("iss"),
        token_claims={"tid": claims.get("tid"), "oid": claims.get("oid"), "aud": claims.get("aud")},
    )


def parse_bearer_token(authorization_header: str | None) -> str:
    if not authorization_header or not authorization_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required.")
    return authorization_header.split(" ", 1)[1].strip()


def safe_token_issuer_host(issuer: str | None) -> str | None:
    if not issuer:
        return None
    parsed = urlparse(issuer)
    return parsed.netloc or None
