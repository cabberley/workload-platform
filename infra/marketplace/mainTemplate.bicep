// mainTemplate.bicep — Azure Marketplace **managed application** entry template (issue #67, Phase 2
// SCAFFOLD). It is a THIN WRAPPER that simply forwards the customer-supplied, non-secret parameters
// (captured by createUiDefinition.json) into the EXISTING platform Bicep (../bicep/main.bicep) —
// keeping a single source of truth. Compiling this file inlines the whole platform into a
// self-contained mainTemplate.json (no external linked-template artifacts), which is what the
// Marketplace managed-app package ships.
//
// Managed apps deploy into the managed resource group at resourceGroup scope, which matches
// main.bicep's own targetScope — so no scope translation is needed.
//
// Keyless / in-boundary / least-privilege are inherited unchanged from main.bicep: every component
// runs as its own user-assigned Managed Identity, no secrets/keys/connection strings appear here,
// and every resource lands in the managed resource group's region (data residency by construction).
//
// TODO(human): Phase-2 completion — the ONE external input still required is the Marketplace
// PUBLISHER ACCOUNT / OFFER IDENTITY (Partner Center publisher id + offer/plan ids), AND the tied
// UNRESOLVED decision on the container-IMAGE SOURCE + STAGING step. As scaffolded, the platform core
// (infra/bicep/modules/core.bicep) CREATES the ACR in the managed resource group, so it starts EMPTY
// — a turnkey image pull does NOT work today. The publisher must decide how images reach that
// registry (e.g. an ACR import/build step run in the managed RG that copies from a publisher-owned
// source registry the deployment identity has AcrPull on) before self-service deploy is turnkey.
// See infra/marketplace/README.md.
targetScope = 'resourceGroup'

@description('Azure region for all resources. Defaults to the managed resource group region so data residency holds by construction.')
param location string = resourceGroup().location

@description('Azure Container Registry name (without .azurecr.io) the platform images are pulled from. As scaffolded, the platform core (infra/bicep/modules/core.bicep) CREATES this ACR in the managed resource group, so it starts empty — the container images must be STAGED into it after creation (image-source/staging is the unresolved Phase-2 decision; see README TODO). It does NOT support a turnkey image pull today.')
param containerRegistry string

@description('Image tag to deploy (usually the release tag).')
param imageTag string = 'latest'

@description('Manage the state container time-based immutability (WORM) policy from IaC. Set false once the policy has been LOCKED out-of-band.')
param manageStateImmutabilityPolicy bool = true

@description('Entra auth mode for the deployed API. Phase-1 DELIVERED default is "disabled" (Option 3, issue #127) — safe ONLY because the API is internal-only (network-isolated, not publicly exposed). "required" (fail-closed) validates a bearer token on every request and is the hardening path; it MUST be enabled before exposing the API publicly. NOTE: ../bicep/main.bicep keeps its OWN default of "required" for direct deployers; this delivered wrapper defaults to "disabled".')
@allowed([
  'required'
  'disabled'
])
param authMode string = 'disabled'

@description('Entra tenant (directory) id the API validates tokens against. Non-secret. Required (with authAudience) when authMode = required.')
param authTenantId string = ''

@description('Expected API token audience (the API app registration Application ID URI / client id). Non-secret. Required (with authTenantId) when authMode = required.')
param authAudience string = ''

// Forward every parameter into the existing platform template — one source of truth.
module platform '../bicep/main.bicep' = {
  name: 'aegis-platform'
  params: {
    location: location
    containerRegistry: containerRegistry
    imageTag: imageTag
    manageStateImmutabilityPolicy: manageStateImmutabilityPolicy
    authMode: authMode
    authTenantId: authTenantId
    authAudience: authAudience
  }
}

@description('API core INTERNAL FQDN (internal ingress only — reachable from inside the Container Apps environment, not the public internet).')
output apiFqdn string = platform.outputs.apiFqdn

@description('Web SPA public FQDN.')
output webFqdn string = platform.outputs.webFqdn

@description('Managed Grafana endpoint (no secrets).')
output grafanaEndpoint string = platform.outputs.grafanaEndpoint
