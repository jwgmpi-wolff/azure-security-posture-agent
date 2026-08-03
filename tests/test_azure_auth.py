import base64
import json
from subprocess import CompletedProcess

from app.services.azure_auth import _parse_expires_on, _wrap_az_command, acquire_cli_principal


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