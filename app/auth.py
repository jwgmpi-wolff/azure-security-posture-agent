from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, Request, Response, status

from app.config import settings
from app.models import SessionState


SESSION_STORE: dict[str, SessionState] = {}
STATE_STORE: dict[str, dict[str, str]] = {}
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "access_token",
    "refresh_token",
    "client_secret",
    "secret",
    "password",
    "token",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


def redact_value(key: str, value: Any) -> Any:
    lowered = key.lower()
    if lowered in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(key, item) for item in value]
    if isinstance(value, str) and ("bearer " in value.lower() or "accountkey=" in value.lower()):
        return "[REDACTED]"
    return value


def redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: redact_value(key, value) for key, value in payload.items()}


def create_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")
    return verifier, challenge


def register_pkce_state(tenant_id: str, redirect_uri: str) -> tuple[str, str]:
    if redirect_uri not in settings.browser_redirect_allowlist:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Redirect URI is not allowlisted.")
    state = secrets.token_urlsafe(32)
    verifier, challenge = create_pkce_pair()
    STATE_STORE[state] = {
        "tenant_id": tenant_id,
        "redirect_uri": redirect_uri,
        "verifier": verifier,
        "challenge": challenge,
    }
    return state, challenge


def pop_pkce_state(state: str) -> dict[str, str]:
    state_entry = STATE_STORE.pop(state, None)
    if not state_entry:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired browser auth state.")
    return state_entry


def set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_id,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.session_max_age_seconds,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(settings.session_cookie_name, path="/")


def save_session(session: SessionState) -> SessionState:
    session.updated_at_utc = utcnow()
    SESSION_STORE[session.session_id] = session
    return session


def create_session(state: SessionState) -> SessionState:
    return save_session(state)


def delete_session(session_id: str) -> None:
    SESSION_STORE.pop(session_id, None)


def get_session(request: Request) -> SessionState:
    session_id = request.cookies.get(settings.session_cookie_name)
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    session = SESSION_STORE.get(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session not found.")

    if session.principal.expires_on_utc <= utcnow():
        delete_session(session_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired.")

    return session


def require_session(request: Request) -> SessionState:
    return get_session(request)


def decode_jwt_payload_unsafe(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            raise ValueError("Token did not contain a payload segment.")
        payload_segment = parts[1]
        payload_segment += "=" * (-len(payload_segment) % 4)
        payload = base64.urlsafe_b64decode(payload_segment.encode("utf-8"))
        import json

        return json.loads(payload)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid bearer token payload: {exc}") from exc


def validate_tenant_claim(selected_tenant_id: str, token_claims: dict[str, Any]) -> None:
    token_tenant = token_claims.get("tid") or token_claims.get("tenantId")
    if token_tenant != selected_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token tenant does not match the selected tenant.",
        )


def compute_signed_nonce(value: str) -> str:
    key = settings.app_name.encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def safe_auth_context(session: SessionState | None) -> dict[str, Any]:
    if session is None:
        return {
            "authenticated": False,
            "authMode": None,
            "tenantId": None,
            "subscriptionIds": [],
            "expiresOnUtc": None,
        }
    return {
        "authenticated": True,
        "authMode": session.principal.auth_mode,
        "tenantId": session.selected_tenant_id,
        "subscriptionIds": session.selected_subscription_ids,
        "expiresOnUtc": session.principal.expires_on_utc.isoformat(),
    }
