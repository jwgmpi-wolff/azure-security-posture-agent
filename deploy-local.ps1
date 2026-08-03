param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8010,
    [switch]$SkipInstall,
    [switch]$SkipValidation,
    [switch]$SkipBrowser
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Assert-Command {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$InstallGuidance
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required. $InstallGuidance"
    }
}

Write-Host "[1/7] Validating local prerequisites..."
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7 or later is required."
}
Assert-Command -Name "python" -InstallGuidance "Install Python 3.11 or later."
Assert-Command -Name "az" -InstallGuidance "Install Azure CLI and run az login."
Assert-Command -Name "git" -InstallGuidance "Install Git for Windows."

$pythonVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$pythonParts = $pythonVersion.Split(".")
if ([int]$pythonParts[0] -lt 3 -or ([int]$pythonParts[0] -eq 3 -and [int]$pythonParts[1] -lt 11)) {
    throw "Python 3.11 or later is required. Found $pythonVersion."
}

Write-Host "[2/7] Preparing virtual environment..."
if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not $SkipInstall) {
    Write-Host "[3/7] Installing pinned dependencies..."
    & $python -m pip install --upgrade pip | Out-Null
    & $python -m pip install -r requirements.txt | Out-Null
} else {
    Write-Host "[3/7] Dependency installation skipped."
}

if (-not $SkipValidation) {
    Write-Host "[4/7] Running compile and unit-test gates..."
    & $python -m py_compile app\main.py app\models.py
    & $python -m pytest -q

    Write-Host "[5/7] Validating OpenAPI and Microsoft 365 package templates..."
    & $python -c "import json; from pathlib import Path; import yaml; root=Path('m365-agent'); json.loads((root/'manifest.template.json').read_text()); json.loads((root/'declarativeAgent.template.json').read_text()); json.loads((root/'apiPlugin.template.json').read_text()); spec=yaml.safe_load((root/'openapi.template.yaml').read_text()); assert str(spec['openapi']).startswith('3.'); print('OpenAPI and agent templates valid')"
} else {
    Write-Host "[4/7] Compile and unit-test gates skipped."
    Write-Host "[5/7] Contract validation skipped."
}

Write-Host "[6/7] Reading safe Azure CLI context..."
$accountJson = az account show --output json 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Azure CLI authentication is required. Run az login --allow-no-subscriptions and retry."
}
$account = $accountJson | ConvertFrom-Json
Write-Host "Current Tenant:       $($account.tenantId)"
Write-Host "Current Subscription: $($account.name) ($($account.id))"
Write-Host "User Principal Name:  $($account.user.name)"

$env:SECPA_APP_HOST = $HostAddress
$env:SECPA_APP_PORT = "$Port"
$callbackUrl = "http://$HostAddress`:$Port/api/auth/browser/callback"
$env:SECPA_ENTRA_REDIRECT_URI = $callbackUrl
$env:SECPA_BROWSER_REDIRECT_ALLOWLIST = "[`"$callbackUrl`"]"
$localUrl = "http://$HostAddress`:$Port"

Write-Host "[7/7] Starting Azure Security Posture Agent at $localUrl ..."
if (-not $SkipBrowser) {
    Start-Process $localUrl
}

& $python -m uvicorn app.main:app --host $HostAddress --port $Port
