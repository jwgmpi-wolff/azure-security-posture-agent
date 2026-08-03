param(
    [string]$ResourceGroup = "rg-azure-security-posture-agent",
    [Parameter(Mandatory = $true)][string]$Location,
    [string]$AppName = "azure-security-posture-agent",
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$SubscriptionId,
    [Parameter(Mandatory = $true)][string]$EntraClientId,
    [string]$EntraAuthority = "https://login.microsoftonline.com/common",
    [ValidateSet("Consumption")][string]$Sku = "Consumption"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$registryName = ("secposture" + ([guid]::NewGuid().ToString("N").Substring(0, 10))).ToLowerInvariant()

Write-Host "Selecting subscription and preparing deployment context..."
$initialAccountJson = az account show --output json 2>$null
if ($LASTEXITCODE -ne 0) { throw "Azure CLI login is required. Run az login and retry." }

Write-Host "Available Azure tenants:"
$tenantArgs = @(
    "account"
    "tenant"
    "list"
    "--query"
    "[].{tenantId:tenantId,tenantCategory:tenantCategory,defaultDomain:defaultDomain}"
    "--output"
    "table"
)
az @tenantArgs
if ($LASTEXITCODE -ne 0) { throw "Unable to enumerate Azure tenants." }

az account set --subscription $SubscriptionId | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Unable to select the requested subscription." }

$account = az account show --output json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Unable to read the selected Azure context." }
if ($account.tenantId -ne $TenantId) {
    throw "Subscription $SubscriptionId belongs to tenant $($account.tenantId), not requested tenant $TenantId."
}
Write-Host "Deployment Tenant:       $($account.tenantId)"
Write-Host "Deployment Subscription: $($account.name) ($($account.id))"
Write-Host "Signed-in Principal:      $($account.user.name)"
Write-Host "The Entra app registration and delegated consent must already exist; this script does not create or modify identity configuration."

Write-Host "Ensuring resource group exists..."
az group create --name $ResourceGroup --location $Location --output none
if ($LASTEXITCODE -ne 0) { throw "Unable to create or update the resource group." }

$deploymentName = "azure-security-posture-agent-$(Get-Date -Format 'yyyyMMddHHmmss')"

Write-Host "Deploying infrastructure template..."
$deploymentArgs = @(
    "deployment"
    "group"
    "create"
    "--resource-group"
    $ResourceGroup
    "--name"
    $deploymentName
    "--template-file"
    "infra/main.bicep"
    "--parameters"
    "location=$Location"
    "tenantId=$TenantId"
    "clientId=$EntraClientId"
    "authority=$EntraAuthority"
    "containerAppName=$AppName"
    "registryName=$registryName"
    "enableManagedIdentity=true"
    "--output"
    "table"
)
az @deploymentArgs
if ($LASTEXITCODE -ne 0) { throw "Infrastructure deployment failed." }

Write-Host "Verifying Container App AcrPull assignment..."
$principalId = az containerapp identity show --name $AppName --resource-group $ResourceGroup --query principalId --output tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($principalId)) {
    throw "Unable to resolve the Container App managed identity."
}
$registryId = az acr show --name $registryName --resource-group $ResourceGroup --query id --output tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($registryId)) {
    throw "Unable to resolve the Azure Container Registry."
}
$acrPullRole = az role assignment list --scope $registryId --assignee-object-id $principalId --query "[?roleDefinitionName=='AcrPull'].roleDefinitionName | [0]" --output tsv
if ($LASTEXITCODE -ne 0 -or $acrPullRole -ne "AcrPull") {
    throw "AcrPull role is not visible yet. Rerun this script after RBAC propagation completes."
}

Write-Host "Building and deploying the container image..."
.\build-and-deploy-containerapp.ps1 -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -AppName $AppName -RegistryName $registryName -TenantId $TenantId -EntraClientId $EntraClientId -EntraAuthority $EntraAuthority -EnableManagedIdentity

if (-not [string]::IsNullOrWhiteSpace($env:SECPA_ENTRA_CLIENT_SECRET)) {
    Write-Host "Configuring the hosted OBO credential from the process environment..."
    az containerapp secret set `
        --name $AppName `
        --resource-group $ResourceGroup `
        --secrets "obo-client-secret=$env:SECPA_ENTRA_CLIENT_SECRET" `
        --output none
    if ($LASTEXITCODE -ne 0) { throw "Unable to configure the hosted OBO credential." }

    az containerapp update `
        --name $AppName `
        --resource-group $ResourceGroup `
        --set-env-vars "SECPA_ENTRA_CLIENT_SECRET=secretref:obo-client-secret" `
        --output none
    if ($LASTEXITCODE -ne 0) { throw "Unable to attach the hosted OBO credential reference." }
}

$fqdn = az containerapp show --name $AppName --resource-group $ResourceGroup --query "properties.configuration.ingress.fqdn" --output tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($fqdn)) { throw "Unable to resolve the deployed application URL." }
Write-Host "Azure deployment complete: https://$($fqdn.Trim())"
