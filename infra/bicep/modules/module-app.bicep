// module-app.bicep — deploy a `kind: service` module as its own Azure Container App with its own
// KEDA scale rule. One of these per service module => modules scale independently.
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

@description('KEDA scale rules (queue/cpu/http) for THIS module only')
param scaleRules array = []

@description('Extra env vars')
param envVars array = []

resource app 'Microsoft.App/containerApps@2024-03-01' = {
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
