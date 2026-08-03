param(
    [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
    [string]$OAuthReferenceId = "azure-security-posture-oauth",
    [Parameter(Mandatory = $true)][string]$TenantIdOrDomain,
    [Parameter(Mandatory = $true)][string]$ContactEmail,
    [Parameter(Mandatory = $true)][string]$OAuthClientId
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

python -c "from pathlib import Path; from app.services.package_builder import build_m365_package; print(build_m365_package(repo_root=Path('.'), api_base_url=r'$ApiBaseUrl', oauth_reference_id=r'$OAuthReferenceId', tenant_id_or_domain=r'$TenantIdOrDomain', contact_email=r'$ContactEmail', oauth_client_id=r'$OAuthClientId'))"