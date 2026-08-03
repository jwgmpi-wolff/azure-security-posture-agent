import asyncio
import base64
import json
from subprocess import CompletedProcess
from urllib.parse import parse_qs, urlparse

from app.services.azure_auth import _parse_expires_on, _wrap_az_command, acquire_cli_principal, build_authorization_url, validate_jwt_token


def test_browser_authorization_forces_account_selection() -> None:
    authorization_url = build_authorization_url(
        "tenant-2",
        "http://127.0.0.1:8010/api/auth/browser/callback",
        "state",
        "challenge",
    )

    query = parse_qs(urlparse(authorization_url).query)

    assert query["prompt"] == ["select_account"]
    assert "/tenant-2/oauth2/v2.0/authorize" in authorization_url


def test_arm_v1_token_uses_tenant_v1_openid_issuer(monkeypatch) -> None:
    token_payload = base64.urlsafe_b64encode(json.dumps({"tid": "tenant-1", "ver": "1.0"}).encode()).decode().rstrip("=")
    token = f"header.{token_payload}.signature"
    expected_issuer = "https://sts.windows.net/tenant-1/"
    captured: dict[str, str] = {}

    async def fake_fetch(tenant_id: str, token_version: str):
        captured["metadata"] = f"{tenant_id}:{token_version}"
        return {"jwks_uri": "https://login.microsoftonline.com/common/discovery/keys", "issuer": expected_issuer}

    class FakeJwkClient:
        def __init__(self, jwks_uri: str):
            captured["jwks_uri"] = jwks_uri

        def get_signing_key_from_jwt(self, encoded_token: str):
            return type("SigningKey", (), {"key": "signing-key"})()

    def fake_decode(encoded_token, signing_key, **kwargs):
        captured["issuer"] = kwargs["issuer"]
        return {"tid": "tenant-1", "ver": "1.0", "iss": expected_issuer, "aud": "https://management.azure.com/"}

    monkeypatch.setattr("app.services.azure_auth.fetch_openid_configuration", fake_fetch)
    monkeypatch.setattr("app.services.azure_auth.PyJWKClient", FakeJwkClient)
    monkeypatch.setattr("app.services.azure_auth.jwt.decode", fake_decode)

    claims = asyncio.run(validate_jwt_token(token, "tenant-1", "https://management.azure.com/"))

    assert claims["iss"] == expected_issuer
    assert captured["metadata"] == "tenant-1:1.0"
    assert captured["issuer"] == expected_issuer


def test_parse_expires_on_accepts_azure_cli_windows_format() -> None:
    expires_on = _parse_expires_on("2099-08-03 18:30:00.000000")

    assert expires_on.year == 2099


def test_azure_cli_command_preserves_executable_path_with_spaces() -> None:
    az_cmd = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd"

    command = _wrap_az_command(az_cmd, ["account", "get-access-token"])

    assert command == [az_cmd, "account", "get-access-token"]


def test_cli_principal_discovers_token_tenant_when_request_is_blank(monkeypatch) -> None:
    token_payload = base64.urlsafe_b64encode(json.dumps({"tid": "tenant-1"}).encode()).decode().rstrip("=")
    token = f"header.{token_payload}.signature"
    captured_command: list[str] = []

    def fake_run(command, **kwargs):
        captured_command.extend(command)
        return CompletedProcess(command, 0, json.dumps({"accessToken": token, "expiresOn": "2000000000"}), "")

    monkeypatch.setattr("app.services.azure_auth._resolve_az_command", lambda: "C:\\Program Files\\Azure CLI\\az.cmd")
    monkeypatch.setattr("app.services.azure_auth.subprocess.run", fake_run)

    principal = acquire_cli_principal("")

    assert principal.tenant_id == "tenant-1"
    assert "--tenant" not in captured_command