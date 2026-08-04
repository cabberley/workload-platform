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
@description('Event jobs: minimum concurrent executions. Not applicable to Schedule jobs.')
param minExecutions int = 0

@description('Event jobs: maximum concurrent executions. For Schedule jobs this maps to ACA `parallelism` (replicas launched per scheduled run).')
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

@description('Internal base URL of the API core (single writer) the worker reads state from and submits results to, e.g. https://wp-api.internal.<env>.azurecontainerapps.io. Threaded from the API container-app\'s internal ingress FQDN by main.bicep so it is correct by construction (never a hardcoded host).')
param apiBaseUrl string = ''

@description('Extra environment variables for this job\'s container (array of { name, value }). Used to thread module-specific, non-secret config (e.g. the telemetry_export DCE endpoint + DCR immutable id) without baking it into this generic template. Defaults to none.')
param extraEnv array = []

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

// Worker env: identity + which module to run. WP_API_BASE_URL points the compute-only worker at
// the API's INTERNAL ingress (the single writer) for both read-back (ApiStateReader) and result
// submission; it is threaded from the API container-app FQDN by main.bicep. It is only appended
// when supplied, so this module never bakes in a hostname.
var baseEnv = [
  { name: 'AZURE_CLIENT_ID', value: identityClientId }
  { name: 'WP_MODULE', value: moduleName }
]
var apiEnv = empty(apiBaseUrl) ? [] : [
  { name: 'WP_API_BASE_URL', value: apiBaseUrl }
]
var containerEnv = concat(baseEnv, apiEnv, extraEnv)

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
        // Schedule jobs honor parallelism/replicaCompletionCount — NOT min/max executions (those are
        // an Event-scale concept). A scheduled single-pass module runs ONE replica per fire, so both
        // are 1; the manifest's maxReplicas is not applicable to schedule cadence (a future sharded
        // discovery could raise this). min/maxExecutions are intentionally unused here.
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
          env: containerEnv
        }
      ]
    }
  }
}

output jobName string = job.name
