from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid5
from zipfile import ZIP_DEFLATED, ZipFile


TEXT_EXTENSIONS = {".json", ".yaml", ".yml", ".md", ".txt"}


def _render_template(text: str, substitutions: dict[str, str]) -> str:
    rendered = text
    for key, value in substitutions.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", value)
    return rendered


def build_m365_package(
    *,
    repo_root: Path,
    api_base_url: str,
    oauth_reference_id: str = "azure-security-posture-oauth",
    tenant_id_or_domain: str = "organizations",
    contact_email: str = "security@example.invalid",
    oauth_client_id: str,
    oauth_authority: str | None = None,
) -> Path:
    package_root = repo_root / "m365-agent"
    output_dir = package_root / "dist"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "azure-security-posture-agent.zip"
    api_base_url = api_base_url.rstrip("/")
    parsed_api_url = urlparse(api_base_url)
    if parsed_api_url.scheme != "https" or not parsed_api_url.netloc:
        raise ValueError("ApiBaseUrl must be an absolute HTTPS URL.")
    if "@" not in contact_email:
        raise ValueError("ContactEmail must be a valid email address.")
    if not oauth_client_id:
        raise ValueError("OAuthClientId is required.")
    substitutions = {
        "API_BASE_URL": api_base_url,
        "API_HOST": parsed_api_url.netloc,
        "OAUTH_REFERENCE_ID": oauth_reference_id,
        "TENANT_ID_OR_DOMAIN": tenant_id_or_domain,
        "CONTACT_EMAIL": contact_email,
        "MANIFEST_ID": str(uuid5(NAMESPACE_URL, f"{tenant_id_or_domain}:azure-security-posture-agent")),
        "OAUTH_CLIENT_ID": oauth_client_id,
        "OAUTH_AUTHORITY": (oauth_authority or f"https://login.microsoftonline.com/{tenant_id_or_domain}").rstrip("/"),
    }

    included_paths = [
        (package_root / "manifest.template.json", "manifest.json"),
        (package_root / "declarativeAgent.template.json", "declarativeAgent.json"),
        (package_root / "apiPlugin.template.json", "apiPlugin.json"),
        (package_root / "openapi.template.yaml", "openapi.yaml"),
        (package_root / "color.png", "color.png"),
        (package_root / "outline.png", "outline.png"),
    ]

    with ZipFile(output_path, "w", ZIP_DEFLATED) as archive:
        for path, relative_name in included_paths:
            if path.suffix.lower() in TEXT_EXTENSIONS:
                archive.writestr(relative_name, _render_template(path.read_text(encoding="utf-8"), substitutions))
            else:
                archive.write(path, relative_name)
    return output_path
