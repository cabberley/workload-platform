<#
.SYNOPSIS
  Guided, keyless, reproducible deploy of the Workloads Platform (Aegis) into the customer's OWN
  Azure subscription — the Windows / PowerShell equivalent of infra/deploy/deploy.sh (issue #67,
  Phase 1). Mirrors .github/workflows/release.yml but runs from a workstation or Azure Cloud Shell.

.DESCRIPTION
  All keyless — uses your existing `az login` (device code / Managed Identity / OIDC). NO secrets,
  keys, or admin credentials are read or written. Steps:
    1. Preflight  — confirm az is present and you are logged in.
    2. Bootstrap  — ensure the resource group + Azure Container Registry exist (admin DISABLED).
    3. Build      — build api/worker/web with `az acr build` (server-side, keyless). Skip with -SkipBuild.
    4. Deploy     — `az deployment group create` over infra/bicep/main.bicep (each module its own ACA app/Job).
    5. Enforce    — scripts/cleanup_verify_state_writers.py: API identity is the ONLY state writer (#79/#97).
    6. Report     — print api / web / Grafana endpoints.
  Everything is parameterized — NO subscription/tenant/resource-group/region is hardcoded.

.EXAMPLE
  ./deploy.ps1 -Subscription 00000000-0000-0000-0000-000000000000 -ResourceGroup rg-aegis `
               -Location australiaeast -AcrName acraegis01 `
               -AuthTenantId <tenant-guid> -AuthAudience api://aegis-workloads-platform
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Subscription,
  [Parameter(Mandatory = $true)][string]$ResourceGroup,
  [Parameter(Mandatory = $true)][string]$Location,
  [Parameter(Mandatory = $true)][Alias('Acr')][string]$AcrName,
  [string]$ImageTag,
  [string]$AuthTenantId = '',
  [string]$AuthAudience = '',
  # Phase-1 DELIVERED default (Option 3, #127): 'disabled' is safe ONLY because the API is
  # internal-only (network-isolated, not publicly exposed). Pass -AuthMode required (with tenant +
  # audience) to harden. main.bicep's OWN code default stays 'required' (fail-closed).
  [ValidateSet('required', 'disabled')][string]$AuthMode = 'disabled',
  [ValidateSet('true', 'false')][string]$ManageWorm = 'true',
  [switch]$SkipBuild,
  [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'

# $ErrorActionPreference='Stop' does NOT trap a native executable's non-zero exit — az failures would
# otherwise be swallowed and the script would continue (e.g. against the wrong/previous subscription)
# and still report success. Route EVERY az call through this helper so any az error fails closed.
function Invoke-Az {
  az @args
  if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed (exit $LASTEXITCODE)" }
}

# Resolve repo root from this script's location (repo/infra/deploy/deploy.ps1).
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path

# Default the image tag to a UTC timestamp so every deploy is uniquely, reproducibly identifiable.
if ([string]::IsNullOrWhiteSpace($ImageTag)) { $ImageTag = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss') }

if ($AuthMode -eq 'required' -and ([string]::IsNullOrWhiteSpace($AuthTenantId) -or [string]::IsNullOrWhiteSpace($AuthAudience))) {
  Write-Warning @'
-AuthMode is 'required' (the fail-closed default) but -AuthTenantId / -AuthAudience were not both
supplied. The platform will DEPLOY, but the API core will REFUSE TO SERVE until a bearer-token
tenant + audience are configured (issue #64). Supply both now, or pass -AuthMode disabled ONLY for
a deliberate no-auth trial environment.
'@
}

# ---- 1. Preflight (keyless — rely on the caller's existing `az login`) ----
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw "Azure CLI (az) not found on PATH. Install: https://aka.ms/azcli" }
az account show 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Not logged in. Run 'az login' (keyless) first." }

Write-Host "==> Selecting subscription $Subscription"
Invoke-Az account set --subscription $Subscription | Out-Null

# Confirm the active subscription is actually the requested one (match by id OR name) — never proceed
# against a stale/previous subscription.
$active = Invoke-Az account show -o json | ConvertFrom-Json
if ($active.id -ne $Subscription -and $active.name -ne $Subscription) {
  throw "Active subscription '$($active.name)' ($($active.id)) does not match requested '$Subscription'."
}

Write-Host "==> Deploy plan"
Write-Host "    subscription : $Subscription"
Write-Host "    resourceGroup: $ResourceGroup"
Write-Host "    location     : $Location"
Write-Host "    acr          : $AcrName (admin disabled - keyless)"
Write-Host "    imageTag     : $ImageTag"
Write-Host "    authMode     : $AuthMode"
Write-Host "    manageWorm   : $ManageWorm"
Write-Host "    skipBuild    : $($SkipBuild.IsPresent)"

# ---- what-if SHORT-CIRCUIT (Finding 5): a preview must have NO side effects. Evaluate -WhatIfOnly
#      BEFORE any mutation (RG create, ACR create, image build/push) and, when set, run ONLY the
#      deployment what-if preview and exit. The normal path below is unchanged. ----
$DeployName = "wp-$ImageTag"
$MainBicep = Join-Path $RepoRoot 'infra/bicep/main.bicep'
$CommonParams = @(
  "location=$Location",
  "containerRegistry=$AcrName",
  "imageTag=$ImageTag",
  "manageStateImmutabilityPolicy=$ManageWorm",
  "authMode=$AuthMode",
  "authTenantId=$AuthTenantId",
  "authAudience=$AuthAudience"
)

if ($WhatIfOnly) {
  Write-Host "==> what-if (preview only - no RG/ACR create, no image build/push, no changes applied)"
  Invoke-Az deployment group what-if --resource-group $ResourceGroup --template-file $MainBicep --parameters $CommonParams
  Write-Host "==> what-if complete (nothing created, built, or deployed)."
  return
}

# ---- 2. Bootstrap RG + ACR (idempotent; ACR admin stays DISABLED — keyless AcrPull via MI) ----
Write-Host "==> Ensuring resource group $ResourceGroup"
Invoke-Az group create --name $ResourceGroup --location $Location --only-show-errors | Out-Null

Write-Host "==> Ensuring Azure Container Registry $AcrName (admin disabled)"
Invoke-Az acr create --resource-group $ResourceGroup --name $AcrName --sku Basic `
  --admin-enabled false --location $Location --only-show-errors | Out-Null

# ---- 3. Build & push images server-side (az acr build — no local Docker, keyless push) ----
if ($SkipBuild) {
  Write-Host "==> Skipping image build (-SkipBuild); deploying existing tag $ImageTag"
}
else {
  foreach ($img in @('api', 'worker', 'web')) {
    Write-Host "==> Building & pushing image workloads-platform/${img}:$ImageTag"
    Invoke-Az acr build --registry $AcrName `
      --image "workloads-platform/${img}:$ImageTag" `
      --image "workloads-platform/${img}:latest" `
      --file (Join-Path $RepoRoot "infra/docker/Dockerfile.$img") `
      $RepoRoot
  }
}

# ---- 4. Deploy the platform Bicep. (-WhatIfOnly was already handled up-front, before any mutation.) ----
Write-Host "==> Deploying $DeployName"
Invoke-Az deployment group create --resource-group $ResourceGroup --name $DeployName `
  --template-file $MainBicep --parameters $CommonParams

# ---- 5. Enforce API-only-writer boundary (#79/#97) — no-op greenfield, fail-closed brownfield ----
Write-Host "==> Enforcing API-only-writer boundary"
$OutputsJson = Invoke-Az deployment group show --resource-group $ResourceGroup --name $DeployName --query properties.outputs -o json
$Outputs = $OutputsJson | ConvertFrom-Json
$SaId = $Outputs.storageAccountId.value
$ApiPid = $Outputs.apiIdentityPrincipalId.value

$env:PYTHONPATH = (Join-Path $RepoRoot 'src')
python (Join-Path $RepoRoot 'scripts/cleanup_verify_state_writers.py') `
  --scope $SaId --resource-group $ResourceGroup --allow $ApiPid --cleanup
if ($LASTEXITCODE -ne 0) { throw "API-only-writer enforcement failed (fail-closed)" }

# ---- 6. Report endpoints ----
Write-Host "==> Deployed endpoints"
Write-Host ("  API (internal): https://{0}" -f $Outputs.apiFqdn.value)
Write-Host ("  Web           : https://{0}" -f $Outputs.webFqdn.value)
Write-Host ("  Grafana       : {0}" -f $Outputs.grafanaEndpoint.value)

Write-Host "==> Done. See docs/delivery/customer-deployment.md for post-deploy verification."
