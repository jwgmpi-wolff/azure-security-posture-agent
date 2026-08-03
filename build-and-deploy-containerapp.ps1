param(
    [Parameter(Mandatory = $true)][string]$SubscriptionId,
    [string]$ResourceGroup = "rg-azure-security-posture-agent",
    [string]$AppName = "azure-security-posture-agent",
    [Parameter(Mandatory = $true)][string]$RegistryName,
    [string]$Repository = "azure-security-posture-agent",
    [string]$ImageTag = "latest",
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$EntraClientId,
    [string]$EntraAuthority = "https://login.microsoftonline.com/common",
    [string]$AllowedOrigins = "",
    [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")][string]$LogLevel = "INFO",
    [bool]$StrictValidationDefault = $true,
    [switch]$SkipSmokeTests,
    [switch]$EnableManagedIdentity
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$imageName = "$RegistryName.azurecr.io/$Repository`:$ImageTag"

$accountArgs = @(
    "account"
    "set"
    "--subscription"
    $SubscriptionId
)
az @accountArgs | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Unable to select the requested subscription." }

Write-Host "Building image in Azure Container Registry..."
$buildArgs = @(
    "acr"
    "build"
    "--registry"
    $RegistryName
    "--image"
    "$Repository`:$ImageTag"
    "."
    "--output"
    "table"
)
az @buildArgs
if ($LASTEXITCODE -ne 0) { throw "ACR image build failed." }

$fqdnArgs = @(
    "containerapp"
    "show"
    "--name"
    $AppName
    "--resource-group"
    $ResourceGroup
    "--query"
    "properties.configuration.ingress.fqdn"
    "--output"
    "tsv"
)
$fqdn = az @fqdnArgs
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($fqdn)) {
    throw "Unable to resolve the Container App FQDN."
}
$appUrl = "https://$($fqdn.Trim())"
if ([string]::IsNullOrWhiteSpace($AllowedOrigins)) {
    $AllowedOrigins = "[`"$appUrl`"]"
}

Write-Host "Attaching Azure Container Registry through the Container App managed identity..."
$registryArgs = @(
    "containerapp"
    "registry"
    "set"
    "--name"
    $AppName
    "--resource-group"
    $ResourceGroup
    "--server"
    "$RegistryName.azurecr.io"
    "--identity"
    "system"
    "--output"
    "none"
)
az @registryArgs
if ($LASTEXITCODE -ne 0) { throw "Container App registry attachment failed." }

Write-Host "Updating Container App image and safe environment variables..."
$updateArgs = @(
    "containerapp"
    "update"
    "--name"
    $AppName
    "--resource-group"
    $ResourceGroup
    "--image"
    $imageName
    "--set-env-vars"
    "SECPA_ENTRA_CLIENT_ID=$EntraClientId"
    "SECPA_ENTRA_AUTHORITY=$EntraAuthority"
    "SECPA_COPILOT_AUDIENCE=api://$EntraClientId"
    "SECPA_ALLOWED_ORIGINS=$AllowedOrigins"
    "SECPA_LOG_LEVEL=$LogLevel"
    "SECPA_STRICT_VALIDATION_DEFAULT=$($StrictValidationDefault.ToString().ToLowerInvariant())"
    "SECPA_ENTRA_REDIRECT_URI=$appUrl/api/auth/browser/callback"
    "SECPA_BROWSER_REDIRECT_ALLOWLIST=[`"$appUrl/api/auth/browser/callback`"]"
    "--output"
    "table"
)
az @updateArgs
if ($LASTEXITCODE -ne 0) { throw "Container App update failed." }

Write-Host "Switching ingress to the application port..."
$ingressArgs = @(
    "containerapp"
    "ingress"
    "update"
    "--name"
    $AppName
    "--resource-group"
    $ResourceGroup
    "--target-port"
    "8000"
    "--output"
    "none"
)
az @ingressArgs
if ($LASTEXITCODE -ne 0) { throw "Container App ingress update failed." }

if (-not $SkipSmokeTests) {
    Write-Host "Running post-deployment smoke tests..."
    $healthResponse = Invoke-WebRequest -Uri "$appUrl/api/health" -Method Get -SkipHttpErrorCheck
    if ($healthResponse.StatusCode -ne 200) {
        throw "Health smoke test failed with HTTP $($healthResponse.StatusCode)."
    }
    try {
        $healthPayload = $healthResponse.Content | ConvertFrom-Json
    }
    catch {
        throw "Health smoke test did not return the application JSON contract."
    }
    if ($healthPayload.status -ne "ok") {
        throw "Health smoke test returned an unexpected application status."
    }

    $authResponse = Invoke-WebRequest -Uri "$appUrl/api/auth/context" -Method Get -SkipHttpErrorCheck
    if ($authResponse.StatusCode -notin @(200, 401)) {
        throw "Authentication boundary smoke test failed with HTTP $($authResponse.StatusCode)."
    }
    Write-Host "Smoke tests passed: health=200, auth-context=$($authResponse.StatusCode)."
}

Write-Host "Container App update completed at $appUrl. No secrets were printed."
