// core.bicep — shared platform: Log Analytics, ACA managed environment, user-assigned identity,
// Key Vault, and a storage account (state + KEDA queues). Everything keyless via Managed Identity.
@description('Azure region')
param location string = resourceGroup().location

@description('Short name prefix for resources')
param namePrefix string = 'wp'

@description('Resource token to keep names unique')
param resourceToken string = uniqueString(resourceGroup().id)

var laName = '${namePrefix}-log-${resourceToken}'
var envName = '${namePrefix}-env-${resourceToken}'
var idName = '${namePrefix}-id-${resourceToken}'
var kvName = take('${namePrefix}kv${resourceToken}', 24)
var saName = take('${namePrefix}st${resourceToken}', 24)

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: idName
  location: location
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
    minimumTlsVersion: 'TLS1_2'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
  }
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: envName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

output environmentId string = env.id
output identityId string = identity.id
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId
output storageName string = storage.name
output keyVaultName string = keyVault.name
output logAnalyticsId string = logAnalytics.id
