// main.bicep — orchestrator. Provisions the shared in-boundary platform (core.bicep), the modest
// API core + web (the single writer stays small), then stamps EACH of the six capability modules
// as its OWN independently-scalable ACA app (kind: service) or ACA Job (kind: job).
//
// Every scale number below is MIRRORED from that module's src/modules/<name>/manifest.yaml
// scaleProfile (kind / minReplicas / maxReplicas / triggers / cpu / memoryGi). The manifest is the
// source of truth — do not hand-tune these here; change the manifest and re-mirror.
//
// Keyless throughout: images pull via AcrPull, queue scalers authenticate with the user-assigned
// Managed Identity (no connection strings). Deployed in-boundary by the release workflow.
targetScope = 'resourceGroup'

@description('Azure region')
param location string = resourceGroup().location

@description('Azure Container Registry name (without .azurecr.io). Created by core.bicep.')
param containerRegistry string

@description('Image tag to deploy (usually the release tag)')
param imageTag string = 'latest'

// Long-running service modules run the persistent service entrypoint (cli.serve), which stays alive
// and dispatches the module named by WP_MODULE. Jobs use cli.worker (run-once) via module-job.
var serviceCommand = [ 'python', '-m', 'cli.serve' ]

module core 'modules/core.bicep' = {
  name: 'core'
  params: {
    location: location
    registryName: containerRegistry
  }
}

// ======================================================================================
// API core + web — the platform, NOT modules. The API core is the single writer, so it
// stays modest (http-concurrency scaling) while the six modules below scale independently.
// (These use their own images' default entrypoints — no command override.)
// ======================================================================================
var coreServices = [
  { name: 'api', image: 'api', min: 1, max: 3, cpu: '0.5',  mem: '1.0Gi', http: 50 }
  { name: 'web', image: 'web', min: 1, max: 3, cpu: '0.25', mem: '0.5Gi', http: 100 }
]

module coreApps 'modules/module-app.bicep' = [for s in coreServices: {
  name: 'app-${s.name}'
  params: {
    location: location
    environmentId: core.outputs.environmentId
    identityId: core.outputs.identityId
    identityClientId: core.outputs.identityClientId
    storageName: core.outputs.storageName
    registry: containerRegistry
    imageTag: imageTag
    moduleName: s.name
    image: s.image
    minReplicas: s.min
    maxReplicas: s.max
    cpu: s.cpu
    memoryGi: s.mem
    httpConcurrency: s.http
  }
}]

// ======================================================================================
// Service modules (kind: service) — long-running ACA apps, each with its own KEDA rules.
// Mirrors src/modules/{aiops,alerts}/manifest.yaml exactly.
//   aiops : min 1  max 20  cpu 1.0  mem 2.0Gi  triggers azure-queue(telemetry) + cpu(70)
//   alerts: min 1  max 10  cpu 0.5  mem 1.0Gi  triggers azure-queue(findings)
// ======================================================================================
var serviceModules = [
  { name: 'aiops',  min: 1, max: 20, cpu: '1.0', mem: '2.0Gi', queue: 'telemetry', cpuUtil: 70 }
  { name: 'alerts', min: 1, max: 10, cpu: '0.5', mem: '1.0Gi', queue: 'findings',  cpuUtil: 0 }
]

module serviceApps 'modules/module-app.bicep' = [for m in serviceModules: {
  name: 'app-${m.name}'
  params: {
    location: location
    environmentId: core.outputs.environmentId
    identityId: core.outputs.identityId
    identityClientId: core.outputs.identityClientId
    storageName: core.outputs.storageName
    registry: containerRegistry
    imageTag: imageTag
    moduleName: m.name
    image: 'worker'
    command: serviceCommand
    minReplicas: m.min
    maxReplicas: m.max
    cpu: m.cpu
    memoryGi: m.mem
    queueName: m.queue
    cpuUtilization: m.cpuUtil
  }
}]

// ======================================================================================
// Job modules (kind: job) — ACA Jobs, scale-to-zero, each with its own trigger.
// Mirrors src/modules/{discovery,quality_checks,reassessments,dependency_graph}/manifest.yaml.
//   discovery       : min 0 max 10 cpu 0.5 mem 1.0Gi  triggers cron(0 */6 * * *) + azure-queue(discovery)
//   quality_checks  : min 0 max 30 cpu 0.5 mem 1.0Gi  triggers azure-queue(assessments)
//   reassessments   : min 0 max 5  cpu 0.5 mem 1.0Gi  triggers cron(0 3 * * *)
//   dependency_graph: min 0 max 10 cpu 0.5 mem 1.0Gi  triggers azure-queue(dependency)
//
// A single ACA Job has ONE trigger type. Queue-only jobs use Event + a keyless azure-queue scaler.
// Cron jobs use the native Schedule trigger with the exact cronExpression (a KEDA cron scaler does
// NOT mean "run once on schedule").
//
// TODO(human): discovery declares BOTH a cron and an azure-queue trigger. It is deployed here as a
// native Schedule job for its periodic 0 */6 cadence; on-demand/event runs (off the `discovery`
// queue) are to be triggered by the API core starting the Job (or enqueuing) — wire that later.
// ======================================================================================
var jobModules = [
  {
    name: 'discovery'
    triggerType: 'Schedule'
    cronExpression: '0 */6 * * *'
    queue: ''
    min: 0
    max: 10
    cpu: '0.5'
    mem: '1.0Gi'
  }
  {
    name: 'quality_checks'
    triggerType: 'Event'
    cronExpression: ''
    queue: 'assessments'
    min: 0
    max: 30
    cpu: '0.5'
    mem: '1.0Gi'
  }
  {
    name: 'reassessments'
    triggerType: 'Schedule'
    cronExpression: '0 3 * * *'
    queue: ''
    min: 0
    max: 5
    cpu: '0.5'
    mem: '1.0Gi'
  }
  {
    name: 'dependency_graph'
    triggerType: 'Event'
    cronExpression: ''
    queue: 'dependency'
    min: 0
    max: 10
    cpu: '0.5'
    mem: '1.0Gi'
  }
]

module jobApps 'modules/module-job.bicep' = [for m in jobModules: {
  name: 'job-${m.name}'
  params: {
    location: location
    environmentId: core.outputs.environmentId
    identityId: core.outputs.identityId
    identityClientId: core.outputs.identityClientId
    storageName: core.outputs.storageName
    registry: containerRegistry
    imageTag: imageTag
    moduleName: m.name
    triggerType: m.triggerType
    cronExpression: empty(m.cronExpression) ? '0 0 * * *' : m.cronExpression
    queueName: m.queue
    minExecutions: m.min
    maxExecutions: m.max
    cpu: m.cpu
    memoryGi: m.mem
  }
}]

output registryLoginServer string = core.outputs.registryLoginServer
output apiFqdn string = coreApps[0].outputs.fqdn
output webFqdn string = coreApps[1].outputs.fqdn
