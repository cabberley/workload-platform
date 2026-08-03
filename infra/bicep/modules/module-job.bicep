// module-job.bicep — deploy a `kind: job` module as its OWN Azure Container Apps Job with its OWN
// trigger (scale-to-zero). One per job module => modules scale independently.
//
//   * triggerType Schedule => native cron cadence (exact cronExpression), no KEDA rules.
//   * triggerType Event    => KEDA-driven; a keyless azure-queue scaler authenticates with the
//                             user-assigned Managed Identity (api-version 2025-01-01).
//
// NOTE: Job scale rules are FLAT KEDA rules ({ name, type, metadata, identity }) — they are NOT
// nested under a `custom` wrapper (that wrapper is the Container App shape).
param location string
param environmentId string
param identityId string
param identityClientId string
param registry string
param imageTag string

@description('Module name, e.g. discovery')
param moduleName string
param image string = 'worker'
param minExecutions int = 0
param maxExecutions int = 10
param cpu string = '0.5'
param memoryGi string = '1.0Gi'

@description('Trigger type: Schedule | Event | Manual')
param triggerType string = 'Event'

@description('Native Schedule cronExpression (used when triggerType == Schedule)')
param cronExpression string = '0 */6 * * *'

@description('Storage account name backing keyless azure-queue KEDA scalers')
param storageName string = ''

@description('azure-queue KEDA trigger: queue name ("" = none). queueLength uses KEDA default (5).')
param queueName string = ''

// Assemble this job's KEDA scale rules from its declared triggers (FLAT shape, keyless queue auth).
var queueRules = empty(queueName) ? [] : [
  {
    name: 'queue-${queueName}'
    type: 'azure-queue'
    identity: identityId
    metadata: {
      accountName: storageName
      queueName: queueName
      cloud: 'AzurePublicCloud'
    }
  }
]
var scaleRules = queueRules

resource job 'Microsoft.App/jobs@2025-01-01' = {
  name: 'wp-${moduleName}'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identityId}': {} }
  }
  properties: {
    environmentId: environmentId
    configuration: {
      triggerType: triggerType
      replicaTimeout: 1800
      registries: [
        { server: '${registry}.azurecr.io', identity: identityId }
      ]
      scheduleTriggerConfig: triggerType == 'Schedule' ? {
        cronExpression: cronExpression
        parallelism: 1
        replicaCompletionCount: 1
      } : null
      eventTriggerConfig: triggerType == 'Event' ? {
        parallelism: 1
        replicaCompletionCount: 1
        scale: {
          minExecutions: minExecutions
          maxExecutions: maxExecutions
          rules: scaleRules
        }
      } : null
    }
    template: {
      containers: [
        {
          name: moduleName
          image: '${registry}.azurecr.io/workloads-platform/${image}:${imageTag}'
          resources: { cpu: json(cpu), memory: memoryGi }
          args: ['--module', moduleName]
          command: ['python', '-m', 'cli.worker']
          env: [
            { name: 'AZURE_CLIENT_ID', value: identityClientId }
            { name: 'WP_MODULE', value: moduleName }
          ]
        }
      ]
    }
  }
}

output jobName string = job.name
