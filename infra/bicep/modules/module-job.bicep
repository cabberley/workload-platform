// module-job.bicep — deploy a `kind: job` module as its own Azure Container Apps Job with its own
// event/cron scale rule (scale-to-zero). One per job module => modules scale independently.
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
param cronExpression string = '0 */6 * * *'

@description('KEDA scale rules for event-triggered jobs (queue, etc.)')
param scaleRules array = []

resource job 'Microsoft.App/jobs@2024-03-01' = {
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
