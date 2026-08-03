from __future__ import annotations

from pathlib import Path

from app.auth import redact_payload


def test_redaction_and_frontend_token_safety() -> None:
    payload = {
        "authorization": "Bearer abc123",
        "cookie": "session=xyz",
        "nested": {"client_secret": "secret-value", "safe": "visible"},
        "connection": "DefaultEndpointsProtocol=https;AccountKey=abcd",
    }
    redacted = redact_payload(payload)
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["cookie"] == "[REDACTED]"
    assert redacted["nested"]["client_secret"] == "[REDACTED]"
    assert redacted["nested"]["safe"] == "visible"
    assert redacted["connection"] == "[REDACTED]"

    app_js = Path("app/static/app.js").read_text(encoding="utf-8")
    assert "localStorage" not in app_js
    assert "sessionStorage" not in app_js
    assert "access_token" not in app_js.lower()
    assert "refresh_token" not in app_js.lower()