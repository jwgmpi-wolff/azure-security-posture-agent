from __future__ import annotations

from app.config import Settings


def test_url_lists_accept_container_apps_cli_serialization(monkeypatch) -> None:
    origin = "https://security.example.com"
    callback = f"{origin}/api/auth/browser/callback"
    monkeypatch.setenv("SECPA_ALLOWED_ORIGINS", f"[{origin}]")
    monkeypatch.setenv("SECPA_BROWSER_REDIRECT_ALLOWLIST", f"[{callback}]")

    configured = Settings(_env_file=None)

    assert configured.allowed_origins == [origin]
    assert configured.browser_redirect_allowlist == [callback]


def test_url_lists_continue_to_accept_json(monkeypatch) -> None:
    monkeypatch.setenv("SECPA_ALLOWED_ORIGINS", '["https://one.example.com", "https://two.example.com"]')

    configured = Settings(_env_file=None)

    assert configured.allowed_origins == ["https://one.example.com", "https://two.example.com"]