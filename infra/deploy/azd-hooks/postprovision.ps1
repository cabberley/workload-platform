<#
  azd postprovision hook (PowerShell) — Windows variant of postprovision.sh. Enforces the
  API-only-writer boundary (issues #79/#97), the same fail-closed gate the scripted deploy runs.
  No-op on a fresh environment; fails the provision if any principal other than the api identity
  holds a state-write role at the storage account.

  The storage-account id and api identity principal id come from main.bicep's provisioning outputs,
  read via `azd env get-values` (robust across output-name surfacing). Keyless — no secrets.
#>
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir '..\..\..')).Path

$Rg = $env:AZURE_RESOURCE_GROUP
if ([string]::IsNullOrWhiteSpace($Rg)) { throw "AZURE_RESOURCE_GROUP not set (azd sets this during provisioning)" }

$Values = (azd env get-values --output json) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "azd env get-values failed" }
$SaId = $Values.storageAccountId
$ApiPid = $Values.apiIdentityPrincipalId

if ([string]::IsNullOrWhiteSpace($SaId) -or [string]::IsNullOrWhiteSpace($ApiPid)) {
  throw "Could not resolve storageAccountId / apiIdentityPrincipalId from azd outputs"
}

Write-Host "==> [postprovision] Enforcing API-only-writer boundary"
$env:PYTHONPATH = (Join-Path $RepoRoot 'src')
python (Join-Path $RepoRoot 'scripts/cleanup_verify_state_writers.py') `
  --scope $SaId --resource-group $Rg --allow $ApiPid --cleanup
if ($LASTEXITCODE -ne 0) { throw "API-only-writer enforcement failed (fail-closed)" }

Write-Host "==> [postprovision] Writer boundary verified."
