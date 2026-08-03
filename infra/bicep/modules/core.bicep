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
  'discovery'    // discovery module (azure-queue trigger)
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

// Built-in role definition ids (keyless RBAC — least privilege).
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'                      // AcrPull
var storageQueueDataContributorRoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'  // Storage Queue Data Contributor
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'          // Key Vault Secrets User

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

output environmentId string = env.id
output identityId string = identity.id
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId
output storageName string = storage.name
output keyVaultName string = keyVault.name
output logAnalyticsId string = logAnalytics.id
output registryName string = registry.name
output registryLoginServer string = registry.properties.loginServer
