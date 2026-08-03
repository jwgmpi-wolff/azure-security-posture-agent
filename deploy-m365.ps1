param(
    [Parameter(Mandatory = $true)][ValidatePattern('^https://')][string]$ApiBaseUrl,
    [Parameter(Mandatory = $true)][string]$OAuthClientId,
    [Parameter(Mandatory = $true)][string]$ContactEmail,
    [string]$TenantIdOrDomain = "organizations",
    [string]$OAuthReferenceId = "azure-security-posture-oauth",
    [ValidateSet("Personal", "Shared")][string]$Scope = "Personal",
    [switch]$Install
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:ATK_CLI_SKILL = "true"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3.11 or later is required."
}

Write-Host "Building the deterministic Microsoft 365 package..."
.\m365-agent\build-package.ps1 `
    -ApiBaseUrl $ApiBaseUrl.TrimEnd('/') `
    -OAuthReferenceId $OAuthReferenceId `
    -TenantIdOrDomain $TenantIdOrDomain `
    -ContactEmail $ContactEmail `
    -OAuthClientId $OAuthClientId
if ($LASTEXITCODE -ne 0) { throw "Microsoft 365 package generation failed." }

$packagePath = Join-Path $PSScriptRoot "m365-agent\dist\azure-security-posture-agent.zip"
if (-not (Test-Path $packagePath)) { throw "Expected package was not created at $packagePath." }

if (Get-Command atk -ErrorAction SilentlyContinue) {
    Write-Host "Validating the package with Microsoft 365 Agents Toolkit..."
    atk validate --package-file $packagePath -i false
    if ($LASTEXITCODE -ne 0) { throw "Microsoft 365 package validation failed." }
} elseif ($Install) {
    throw "Microsoft 365 Agents Toolkit is required for installation. Install @microsoft/m365agentstoolkit-cli@beta."
} else {
    Write-Warning "Agents Toolkit is not installed; package creation completed without Toolkit validation."
}

if ($Install) {
    Write-Host "Using the current delegated Microsoft 365 account. Authenticate first with: atk auth login m365 --tenant $TenantIdOrDomain"
    atk auth list
    if ($LASTEXITCODE -ne 0) { throw "Unable to verify Microsoft 365 authentication." }

    atk install --file-path $packagePath --scope $Scope -i false
    if ($LASTEXITCODE -ne 0) { throw "Microsoft 365 installation failed." }
    Write-Host "Microsoft 365 installation completed in $Scope scope."
}

Write-Host "Package ready: $packagePath"