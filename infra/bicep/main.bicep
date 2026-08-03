// main.bicep — orchestrator. Deploys shared core, then stamps EACH module as its own
// independently-scalable ACA app (services) or ACA Job (batch). Scale params come from each
// module's manifest scaleProfile (mirrored here). Deployed in-boundary via the release workflow.
targetScope = 'resourceGroup'

@description('Azure region')
param location string = resourceGroup().location

@description('Azure Container Registry name (without .azurecr.io)')
param containerRegistry string

@description('Image tag to deploy (usually the release tag)')
param imageTag string = 'latest'

module core 'modules/core.bicep' = {
  name: 'core'
  params: {
    location: location
  }
}

// ---- Service modules (long-running ACA apps, each with its own scale rule) ----
var serviceModules = [
  { name: 'api',    image: 'api', min: 1, max: 3,  cpu: '0.5', mem: '1.0Gi', rules: [ { name: 'http', http: { metadata: { concurrentRequests: '50' } } } ] }
  { name: 'web',    image: 'web', min: 1, max: 3,  cpu: '0.25', mem: '0.5Gi', rules: [ { name: 'http', http: { metadata: { concurrentRequests: '100' } } } ] }
  { name: 'aiops',  image: 'worker', min: 1, max: 20, cpu: '1.0', mem: '2.0Gi', rules: [ { name: 'cpu', custom: { type: 'cpu', metadata: { type: 'Utilization', value: '70' } } } ] }
  { name: 'alerts', image: 'worker', min: 1, max: 10, cpu: '0.5', mem: '1.0Gi', rules: [ { name: 'queue', custom: { type: 'azure-queue', metadata: { queueName: 'findings', queueLength: '10' } } } ] }
]

module services 'modules/module-app.bicep' = [for m in serviceModules: {
  name: 'app-${m.name}'
  params: {
    location: location
    environmentId: core.outputs.environmentId
    identityId: core.outputs.identityId
    identityClientId: core.outputs.identityClientId
    registry: containerRegistry
    imageTag: imageTag
    moduleName: m.name
    image: m.image
    minReplicas: m.min
    maxReplicas: m.max
    cpu: m.cpu
    memoryGi: m.mem
    scaleRules: m.rules
  }
}]

// ---- Job modules (ACA Jobs, scale-to-zero, cron or event) ----
var jobModules = [
  { name: 'discovery',        trigger: 'Schedule', cron: '0 */6 * * *', min: 0, max: 10 }
  { name: 'quality_checks',   trigger: 'Event',    cron: '',            min: 0, max: 30 }
  { name: 'reassessments',    trigger: 'Schedule', cron: '0 3 * * *',   min: 0, max: 5 }
  { name: 'dependency_graph', trigger: 'Event',    cron: '',            min: 0, max: 10 }
]

module jobs 'modules/module-job.bicep' = [for m in jobModules: {
  name: 'job-${m.name}'
  params: {
    location: location
    environmentId: core.outputs.environmentId
    identityId: core.outputs.identityId
    identityClientId: core.outputs.identityClientId
    registry: containerRegistry
    imageTag: imageTag
    moduleName: m.name
    triggerType: m.trigger
    cronExpression: empty(m.cron) ? '0 0 * * *' : m.cron
    minExecutions: m.min
    maxExecutions: m.max
  }
}]

output apiFqdn string = services[0].outputs.fqdn
output webFqdn string = services[1].outputs.fqdn
