// module-app.bicep — deploy a `kind: service` module as its OWN Azure Container App with its OWN
// KEDA scale rule(s). One of these per service module => modules scale independently.
//
// Scale triggers are expressed declaratively (queue / cpu / http) and assembled here so keyless
// azure-queue scaling authenticates with the user-assigned Managed Identity (api-version
// 2025-01-01 supports scale-rule identity). No connection strings or keys anywhere.
param location string
param environmentId string
param identityId string
param identityClientId string
param registry string
param imageTag string

@description('Module name, e.g. aiops')
param moduleName string
param image string
param minReplicas int = 1
param maxReplicas int = 10
param cpu string = '0.5'
param memoryGi string = '1.0Gi'

@description('Container command override (e.g. the service entrypoint). Empty => use image default.')
param command array = []

@description('Storage account name backing keyless azure-queue KEDA scalers')
param storageName string = ''

@description('azure-queue KEDA trigger: queue name ("" = none). queueLength uses KEDA default (5).')
param queueName string = ''

@description('cpu KEDA trigger: target Utilization percent (0 = none)')
param cpuUtilization int = 0

@description('http KEDA trigger: concurrent requests per replica (0 = none)')
param httpConcurrency int = 0

@description('Extra env vars')
param envVars array = []

// Assemble this module's KEDA scale rules from its declared triggers (keyless queue auth via MI).
var queueRules = empty(queueName) ? [] : [
  {
    name: 'queue-${queueName}'
    custom: {
      type: 'azure-queue'
      identity: identityId
      metadata: {
        accountName: storageName
        queueName: queueName
        cloud: 'AzurePublicCloud'
      }
    }
  }
]
var cpuRules = cpuUtilization == 0 ? [] : [
  {
    name: 'cpu'
    custom: {
      type: 'cpu'
      metadata: {
        type: 'Utilization'
        value: string(cpuUtilization)
      }
    }
  }
]
var httpRules = httpConcurrency == 0 ? [] : [
  {
    name: 'http'
    http: {
      metadata: {
        concurrentRequests: string(httpConcurrency)
      }
    }
  }
]
var scaleRules = concat(queueRules, cpuRules, httpRules)

resource app 'Microsoft.App/containerApps@2025-01-01' = {
  name: 'wp-${moduleName}'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identityId}': {} }
  }
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      activeRevisionsMode: 'Single'
      registries: [
        { server: '${registry}.azurecr.io', identity: identityId }
      ]
      ingress: moduleName == 'api' || moduleName == 'web' ? {
        external: moduleName == 'web'
        targetPort: moduleName == 'api' ? 8000 : 80
        transport: 'auto'
      } : null
    }
    template: {
      containers: [
        {
          name: moduleName
          image: '${registry}.azurecr.io/workloads-platform/${image}:${imageTag}'
          command: empty(command) ? null : command
          resources: { cpu: json(cpu), memory: memoryGi }
          env: concat([
            { name: 'AZURE_CLIENT_ID', value: identityClientId }
            { name: 'WP_MODULE', value: moduleName }
          ], envVars)
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: scaleRules
      }
    }
  }
}

output fqdn string = moduleName == 'api' || moduleName == 'web' ? app.properties.configuration.ingress.fqdn : ''
