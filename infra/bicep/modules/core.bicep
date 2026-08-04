// core.bicep — shared in-boundary platform for every module:
//   * Azure Container Registry (keyless; images pulled via Managed Identity / AcrPull)
//   * Log Analytics workspace + Container Apps managed environment
//   * Storage account + the KEDA queues the module triggers reference
//   * User-assigned Managed Identity (one identity, least-privilege role assignments)
//   * Key Vault (runtime secrets by reference — never in code/outputs)
// Everything is keyless via Managed Identity. No keys/connection strings are emitted as outputs.
@description('Azure region')
param location string = resourceGroup().location

@description('Short name prefix for resources')
@minLength(1)
param namePrefix string = 'wp'

@description('Resource token to keep names unique')
param resourceToken string = uniqueString(resourceGroup().id)

@description('Azure Container Registry name (alphanumeric, globally unique, without .azurecr.io)')
param registryName string

@description('Container Registry SKU')
@allowed([ 'Basic', 'Standard', 'Premium' ])
param registrySku string = 'Basic'

@description('Storage queues the module KEDA triggers reference (mirrors src/modules/*/manifest.yaml).')
param queueNames array = [
  'dependency'   // dependency_graph module (azure-queue trigger)
  'assessments'  // quality_checks module (azure-queue trigger)
  'telemetry'    // aiops module (azure-queue trigger)
  'findings'     // alerts module (azure-queue trigger)
]

var laName = '${namePrefix}-log-${resourceToken}'
var envName = '${namePrefix}-env-${resourceToken}'
var idName = '${namePrefix}-id-${resourceToken}'
var kvName = take('${namePrefix}kv${resourceToken}', 24)
var saName = take('${namePrefix}st${resourceToken}', 24)

// Built-in role definition ids (keyless RBAC — least privilege). Every GUID below was verified with
// `az role definition list --name "<Role Name>" --query "[0].name"` against the target tenant.
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'                      // AcrPull
var storageQueueDataContributorRoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'  // Storage Queue Data Contributor
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'          // Key Vault Secrets User
// Read-plane roles (issue #80). Reader is a management-plane read role; the storage data roles are
// data-plane. None grants any management-plane write (no Contributor at the control plane).
var readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'                        // Reader
var storageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'    // Storage Blob Data Contributor
var storageTableDataContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'   // Storage Table Data Contributor

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: idName
  location: location
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: registryName
  location: location
  sku: { name: registrySku }
  properties: {
    adminUserEnabled: false // keyless: pulls happen via Managed Identity + AcrPull
  }
}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: laName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: saName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // keyless: queue access is via Managed Identity only
    minimumTlsVersion: 'TLS1_2'
  }
}

resource queueService 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource queues 'Microsoft.Storage/storageAccounts/queueServices/queues@2023-05-01' = [for q in queueNames: {
  parent: queueService
  name: q
}]

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
  }
}

resource env 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: envName
  location: location
  properties: {
    // Keyless: emit app logs to Azure Monitor and route them to Log Analytics via a diagnostic
    // setting (below). No Log Analytics shared key is read anywhere.
    appLogsConfiguration: {
      destination: 'azure-monitor'
    }
  }
}

resource envDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-log-analytics'
  scope: env
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      { categoryGroup: 'allLogs', enabled: true }
    ]
  }
}

// ---- Keyless role assignments for the shared module identity (least privilege) ----
// AcrPull so every module can pull its image without a registry credential.
resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identity.id, acrPullRoleId)
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Queue Data Contributor: modules enqueue/dequeue work and KEDA reads queue length.
resource queueDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, storageQueueDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Key Vault Secrets User: runtime secrets are read by identity, never embedded.
resource kvSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identity.id, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---- Read-plane role assignments (issue #80) — least privilege, keyless ----
// The six capability modules share this SINGLE user-assigned identity, so its effective permission
// set is the UNION of what every read-plane client needs. Each grant below names its real Python
// consumer and whether that consumer is wired in deployment today or forward-looking, so the intent
// is deliberate — not accidental over-grant.

// Reader (management-plane */read). Consumers:
//   * Azure Resource Graph discovery — src/modules/discovery/arg.py (AzureResourceGraphClient):
//     read-only KQL over resources (id/name/type/tags). ACTIVE — the discovery Job runs today.
//   * Network-topology reads — src/modules/dependency_graph/topology.py
//     (AzureNetworkTopologyClient): load balancers / application gateways / network interfaces
//     read. FORWARD-LOOKING — the client is injected via ctx.clients["network"] but not yet wired
//     into the deployed job's env; provisioning its least-privilege role now keeps it fail-closed
//     rather than fail-open when wired.
// Reader also transitively covers the Azure Monitor connector's in-RG reads: */read includes
// Microsoft.Insights/*/read (metrics) and Microsoft.OperationalInsights/workspaces/query/*/read
// (Log Analytics). That connector additionally holds explicit Monitoring Reader (RG scope) +
// Log Analytics Reader (workspace scope) on this SAME shared identity from grafana.bicep — so those
// two roles are NOT re-declared here: a second assignment for the same principal+role+scope is
// rejected by Azure with RoleAssignmentExists. See infra/bicep/README.md for the read-plane matrix.
//
// SCOPE — this is a resourceGroup-scoped deployment (main.bicep targetScope = 'resourceGroup'), so
// Reader is assigned at the RESOURCE GROUP: the narrowest scope this template can grant inline. ARG
// discovery reads across the SUBSCRIPTION, so subscription-wide discovery additionally requires a
// SUBSCRIPTION-scope Reader applied SEPARATELY (it cannot be created from an RG-scoped deployment).
// At this RG scope, ARG returns only the in-boundary resources in this resource group. This is
// documented — we do NOT over-claim subscription-wide discovery from an RG grant.
resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, identity.id, readerRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', readerRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Table Data Contributor (data-plane). Consumer: the Azure state backend —
// src/shared/state.py (AzureStateStore) — creates the snapshots/workloads tables and writes the
// manifest entities that are its single commit point (create_table_if_not_exists / create_entity /
// update_entity). It WRITES, so Contributor (not the read-only Table Data Reader) is required —
// least privilege for a read+write consumer. FORWARD-LOOKING: the backend defaults to local and is
// selected only when WORKLOADS_STATE_BACKEND=azure with the state endpoints wired; module-app.bicep
// does not export those env vars yet. Scoped to the storage account (narrowest inline scope).
resource stateTableDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, storageTableDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Blob Data Contributor (data-plane). Consumer: the same Azure state backend
// (AzureStateStore) — creates the state container and uploads the immutable, version-scoped
// estate/graph/findings blobs the manifest points at (create_container / upload_blob), as well as
// reading them back (download_blob). Because it WRITES blobs, Contributor is required, not the
// read-only Storage Blob Data Reader (Contributor ⊇ Reader, so it also covers any read-only
// pack-content blob access under this shared identity). FORWARD-LOOKING alongside the table grant
// above. Scoped to the storage account.
resource stateBlobDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, storageBlobDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

output environmentId string = env.id
output identityId string = identity.id
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId
output storageName string = storage.name
output keyVaultName string = keyVault.name
output logAnalyticsId string = logAnalytics.id
output logAnalyticsName string = logAnalytics.name
output registryName string = registry.name
output registryLoginServer string = registry.properties.loginServer
