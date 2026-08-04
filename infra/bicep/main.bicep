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
// Telemetry visualization — Azure Managed Grafana over Azure Monitor (issue #58, ADR 0007).
// Keyless: the instance reuses the SHARED user-assigned Managed Identity from core (identityId) as
// its DATA-SOURCE (read) identity, granted ONLY least-privilege READ roles (Monitoring Reader +
// Log Analytics Reader) scoped to this resource group — see grafana.bicep for the scope rationale.
// No API keys, no data-source secrets, no board JSON in IaC.
//
// Provisioning the Azure Monitor data source + dashboards is NOT done here: it is performed
// out-of-band by a SEPARATE Entra caller (CI Managed Identity or operator) holding the Grafana
// Editor data-plane role — NOT this shared identity, which only READS Azure Monitor at query time.
// Boards are versioned in infra/grafana and imported via the Grafana API (infra/grafana/README.md).
// ======================================================================================
module grafana 'modules/grafana.bicep' = {
  name: 'grafana'
  params: {
    location: location
    identityResourceId: core.outputs.identityId
    identityPrincipalId: core.outputs.identityPrincipalId
    logAnalyticsName: core.outputs.logAnalyticsName
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
//   discovery       : job(schedule) parallelism 10 cpu 0.5 mem 1.0Gi  triggers cron(0 */6 * * *) + api-invoked
//   quality_checks  : job(event) exec 0->30 cpu 0.5 mem 1.0Gi  triggers azure-queue(assessments)
//   reassessments   : job(schedule) parallelism 5  cpu 0.5 mem 1.0Gi  triggers cron(0 3 * * *)
//   dependency_graph: job(event) exec 0->10 cpu 0.5 mem 1.0Gi  triggers azure-queue(dependency)
//
// Schedule jobs use the native cron trigger; maxExecutions maps to ACA `parallelism` (see
// module-job.bicep). Event (queue-only) jobs use a keyless azure-queue KEDA scaler.
//
// TODO(human): discovery declares a cron trigger AND an `api-invoked` (on-demand) trigger. The
// periodic 0 */6 cadence is the native Schedule below; on-demand runs are started by the API core
// invoking this Job (control-plane `job start`) — wire that API path later. There is deliberately
// no azure-queue trigger for discovery, so nothing is silently dropped.
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
    // Compute-only worker jobs reach the single-writer API over its INTERNAL ingress. Derived
    // from the API container-app's ingress FQDN (coreApps[0] == the 'api' app, deployed as
    // wp-api) so the value is correct by construction — never a hardcoded host. Referencing this
    // output also orders the API app before the jobs.
    apiBaseUrl: 'https://${coreApps[0].outputs.fqdn}'
  }
}]

output registryLoginServer string = core.outputs.registryLoginServer
output apiFqdn string = coreApps[0].outputs.fqdn
output webFqdn string = coreApps[1].outputs.fqdn
// Managed Grafana public endpoint (no secrets). Feed this into the web build-time VITE_GRAFANA_URL
// (the keyless deep-link surface) — Managed Grafana blocks iframing by default, so this raw
// endpoint is NOT an embeddable panel URL. Only set VITE_GRAFANA_PANEL_URL to a separate,
// auth-proxied, embeddable panel URL; never a token in either.
output grafanaEndpoint string = grafana.outputs.grafanaEndpoint
