<#
  azd preprovision hook (PowerShell) — Windows variant of preprovision.sh. Stages the container
  images so the provisioned Bicep can pull them: ensures the ACR core.bicep manages exists
  (idempotent, admin DISABLED — keyless) and builds ALL THREE images (api, worker, web) with
  `az acr build`, including the `worker` image the ACA Jobs depend on.

  Keyless throughout (your azd/az login; no secrets). Images tagged :latest to match main.bicep's
  default imageTag; WP_IMAGE_TAG, if set, is applied as an additional traceability tag.
#>
$ErrorActionPreference = 'Stop'
function Invoke-Az { az @args; if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed (exit $LASTEXITCODE)" } }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir '..\..\..')).Path

$Acr = $env:AZURE_CONTAINER_REGISTRY_NAME
$Rg = $env:AZURE_RESOURCE_GROUP
$Location = $env:AZURE_LOCATION
$Tag = if ([string]::IsNullOrWhiteSpace($env:WP_IMAGE_TAG)) { 'latest' } else { $env:WP_IMAGE_TAG }

if ([string]::IsNullOrWhiteSpace($Acr)) { throw "Set it first: azd env set AZURE_CONTAINER_REGISTRY_NAME <acr-name>" }
if ([string]::IsNullOrWhiteSpace($Rg)) { throw "AZURE_RESOURCE_GROUP not set (azd sets this during provisioning)" }
if ([string]::IsNullOrWhiteSpace($Location)) { throw "AZURE_LOCATION not set (azd sets this from your chosen region)" }

Write-Host "==> [preprovision] Ensuring resource group $Rg in $Location"
Invoke-Az group create --name $Rg --location $Location --only-show-errors | Out-Null

Write-Host "==> [preprovision] Ensuring ACR $Acr (admin disabled)"
Invoke-Az acr create --resource-group $Rg --name $Acr --sku Basic `
  --admin-enabled false --location $Location --only-show-errors | Out-Null

foreach ($img in @('api', 'worker', 'web')) {
  Write-Host "==> [preprovision] Building & pushing workloads-platform/${img} (:latest, :$Tag)"
  Invoke-Az acr build --registry $Acr `
    --image "workloads-platform/${img}:latest" `
    --image "workloads-platform/${img}:$Tag" `
    --file (Join-Path $RepoRoot "infra/docker/Dockerfile.$img") `
    $RepoRoot
}

Write-Host "==> [preprovision] All images staged."
