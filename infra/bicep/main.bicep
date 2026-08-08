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

@description('Manage (create/update) the state container time-based immutability (WORM) policy from IaC (issue #81). Set FALSE once the policy has been LOCKED out-of-band — Azure rejects any PUT on a LOCKED immutability policy, so leaving this true would break every subsequent deployment (core is always deployed).')
param manageStateImmutabilityPolicy bool = true

@description('Entra auth mode for the deployed API (issue #64). Fail-closed by default: "required" means the API validates a bearer token on every request and REFUSES TO SERVE unless authTenantId + authAudience are supplied. Set to "disabled" ONLY for a deliberate no-auth environment. Never a secret.')
param authMode string = 'required'

@description('Entra tenant (directory) id the API validates tokens against, and the worker authenticates from (issue #64). Non-secret identifier. Empty by default — MUST be provided (with authAudience) for the fail-closed "required" default, or the API will refuse to serve.')
param authTenantId string = ''

@description('Expected API token audience — the API app registration Application ID URI / client id (issue #64). Non-secret. Empty by default — MUST be provided (with authTenantId) for the "required" default.')
param authAudience string = ''

// review-67-v4 (HIGH) structural invariant: the PUBLIC web front door is only ever open when the
// API enforces required auth. The web app's nginx reverse-proxies /api/* to the internal API, so a
// public web app with authMode=disabled would expose the unauthenticated API to the internet. By
// coupling web's external ingress to (authMode == 'required') the invariant holds in EVERY
// deployment path, not just by a default value: disabled ⇒ web internal-only ⇒ zero public surface
// ⇒ disabled-auth is safe; required ⇒ web public, but the API enforces bearer auth ⇒ still safe.
var webIngressExternal = authMode == 'required'

// Long-running service modules run the persistent service entrypoint (cli.serve), which stays alive
// and dispatches the module named by WP_MODULE. Jobs use cli.worker (run-once) via module-job.
var serviceCommand = [ 'python', '-m', 'cli.serve' ]

module core 'modules/core.bicep' = {
  name: 'core'
  params: {
    location: location
    registryName: containerRegistry
    // Threaded so an operator can flip it FALSE at deploy time AFTER locking the WORM policy
    // out-of-band (Azure rejects any PUT on a locked immutability policy) — issue #81 / F1.
    manageStateImmutabilityPolicy: manageStateImmutabilityPolicy
  }
}

// ======================================================================================
// Telemetry visualization — Azure Managed Grafana over Azure Monitor (issue #58, ADR 0007).
// Keyless: the instance uses its OWN read-only user-assigned Managed Identity (identityGrafana from
// core, issue #79) as its DATA-SOURCE (read) identity, granted ONLY least-privilege READ roles
// (Monitoring Reader + Log Analytics Reader) scoped as documented in grafana.bicep. It is a
// dedicated read principal — NOT any writer identity — so Grafana can never write state.
//
// Provisioning the Azure Monitor data source + dashboards is NOT done here: it is performed
// out-of-band by a SEPARATE Entra caller (CI Managed Identity or operator) holding the Grafana
// Editor data-plane role — NOT this identity, which only READS Azure Monitor at query time.
// Boards are versioned in infra/grafana and imported via the Grafana API (infra/grafana/README.md).
// ======================================================================================
module grafana 'modules/grafana.bicep' = {
  name: 'grafana'
  params: {
    location: location
    identityResourceId: core.outputs.identityGrafanaId
    identityPrincipalId: core.outputs.identityGrafanaPrincipalId
    logAnalyticsName: core.outputs.logAnalyticsName
  }
}

// ======================================================================================
// Telemetry export provisioning — the emit path for the #58 boards (issue #86).
// Provisions the 4 PII-free custom Log Analytics tables (WpNodeState_CL / WpSpof_CL / WpFinding_CL
// / WpConnectorFetch_CL), a Data Collection Endpoint + Data Collection Rule mapping one stream per
// table into the in-boundary workspace, and a LEAST-PRIVILEGE Monitoring Metrics Publisher grant on
// the DCR to the WORKER identity (which runs the telemetry_export Job). Keyless: the Job publishes
// via the Logs Ingestion API with Managed Identity — no ingestion key anywhere. The DCE endpoint +
// DCR immutable id are non-secret outputs threaded to the Job as env below.
// ======================================================================================
module telemetryExport 'modules/telemetry-export.bicep' = {
  name: 'telemetry-export'
  params: {
    location: location
    logAnalyticsId: core.outputs.logAnalyticsId
    logAnalyticsName: core.outputs.logAnalyticsName
    publisherPrincipalId: core.outputs.identityWorkerPrincipalId
  }
}

// ======================================================================================
// API core + web — the platform, NOT modules. The API core is the single writer, so it
// stays modest (http-concurrency scaling) while the module Jobs/apps below scale independently.
// (These use their own images' default entrypoints — no command override.)
//
// Per-component identities (issue #79): the API runs as the WRITER identity (identityApi — holds the
// state-store write data roles); the web runs as the READER identity (identityWeb — no write role),
// so the "API is the only writer" boundary is enforced by RBAC, not convention.
// ======================================================================================
// The API core (WRITER identity) — INTERNAL ingress only (never internet-facing). Deployed as its
// own module so the web app below can thread its ingress FQDN as the reverse-proxy target (see
// webApp) — an explicit dependency the previous `[for ...]` loop could not express (a loop cannot
// reference its own sibling's output).
module apiApp 'modules/module-app.bicep' = {
  name: 'app-api'
  params: {
    location: location
    environmentId: core.outputs.environmentId
    // API => WRITER identity (holds state-store write roles).
    identityId: core.outputs.identityApiId
    identityClientId: core.outputs.identityApiClientId
    storageName: core.outputs.storageName
    registry: containerRegistry
    imageTag: imageTag
    moduleName: 'api'
    image: 'api'
    minReplicas: 1
    maxReplicas: 3
    cpu: '0.5'
    memoryGi: '1.0Gi'
    httpConcurrency: 50
    // The API is ALWAYS internal — never internet-facing (fail-closed).
    ingressExternal: false
    // The API is the intended runtime-secret reader (holds Key Vault Secrets User); thread the vault
    // URI so its app-side provider can resolve secrets by identity.
    keyVaultUri: core.outputs.keyVaultUri
    // Entra auth (issue #64): ONLY the API core enforces bearer validation (it runs the FastAPI
    // app). Fail-closed by default — with authMode=required the API refuses to serve unless tenant +
    // audience are supplied.
    authMode: authMode
    authTenantId: authTenantId
    authAudience: authAudience
  }
}

// The web SPA (READER identity). Its public (external) ingress is GATED on the auth posture
// (review-67-v4): external ONLY when authMode=='required' (webIngressExternal). Its nginx
// reverse-proxies same-origin `/api/*` to the API's INTERNAL ingress FQDN (issue #67): the SPA runs
// in the customer's browser and cannot reach the internal API directly, so the web container — which
// IS in the Container Apps environment — proxies for it. Because a public web app would expose the
// API's write endpoints through that proxy, the web front door stays INTERNAL while authMode is
// disabled (Phase-1) — zero public surface — and only opens publicly once the API enforces required
// auth. Keyless & in-boundary: the API stays internal-only and enforces its own Entra bearer auth;
// nginx forwards the caller's Authorization header unchanged and injects no credentials.
// WP_API_BASE_URL is derived from the API app's ingress FQDN so it is correct by construction (never
// a hardcoded host); referencing that output also orders the API app before the web app.
module webApp 'modules/module-app.bicep' = {
  name: 'app-web'
  params: {
    location: location
    environmentId: core.outputs.environmentId
    // web => READER identity (no state-store write role).
    identityId: core.outputs.identityWebId
    identityClientId: core.outputs.identityWebClientId
    storageName: core.outputs.storageName
    registry: containerRegistry
    imageTag: imageTag
    moduleName: 'web'
    image: 'web'
    minReplicas: 1
    maxReplicas: 3
    cpu: '0.25'
    memoryGi: '0.5Gi'
    httpConcurrency: 100
    // PUBLIC ingress gated on auth posture: external only when authMode=='required' (see
    // webIngressExternal near the authMode param). Delivered default disabled ⇒ internal-only.
    ingressExternal: webIngressExternal
    // The web SPA reads NO runtime secret and holds no KV role, so it is deliberately excluded
    // (least privilege, issue #85). It also does not enforce server-side auth, so no auth vars.
    keyVaultUri: ''
    authMode: ''
    authTenantId: ''
    authAudience: ''
    // Reverse-proxy target consumed by the web image's nginx template (infra/docker/nginx.conf.template).
    // NB: the object is split across lines so the `{`/`}` never share a line with the `https://`
    // URL literal (keeps the data-residency scanner's line-based brace matching balanced).
    envVars: [
      {
        name: 'WP_API_BASE_URL'
        value: 'https://${apiApp.outputs.fqdn}'
      }
    ]
  }
}

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
    // Service modules run modules => they run as the WRITER worker identity (issue #79).
    identityId: core.outputs.identityWorkerId
    identityClientId: core.outputs.identityWorkerClientId
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
    // aiops reads the System Pulse read token from Key Vault BY the worker Managed Identity (issue
    // #85): the vault URI drives both the ACA `secretRef` below and the app-side provider, which
    // fails closed if the configured vault cannot supply the token. Other modules need no KV secret.
    keyVaultUri: m.name == 'aiops' ? core.outputs.keyVaultUri : ''
    keyVaultSecrets: m.name == 'aiops' ? [
      {
        secretRefName: 'system-pulse-read-token'
        secretName: 'system-pulse-read-token'
        envVar: 'SYSTEM_PULSE_READ_TOKEN'
      }
    ] : []
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
    // Job modules run modules => they run as the WRITER worker identity (issue #79).
    identityId: core.outputs.identityWorkerId
    identityClientId: core.outputs.identityWorkerClientId
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
    // from the API container-app's ingress FQDN (the apiApp module, deployed as
    // wp-api) so the value is correct by construction — never a hardcoded host. Referencing this
    // output also orders the API app before the jobs.
    apiBaseUrl: 'https://${apiApp.outputs.fqdn}'
    // Entra auth (issue #64): when authMode=required the worker mints a bearer for the API audience
    // via its own Managed Identity (#79) before submitting results — no shared key. Threaded so the
    // worker's auth config matches the API it calls. Both tenant + audience are required together
    // (a partial config fails closed).
    authMode: authMode
    authTenantId: authTenantId
    authAudience: authAudience
  }
}]

// ======================================================================================
// Telemetry Export module (kind: job) — its OWN scheduled ACA Job, mirroring
// src/modules/telemetry_export/manifest.yaml (cron */5, cpu 0.25, mem 0.5Gi, scale-to-zero). Kept
// SEPARATE from the jobModules loop above so its container env can be threaded with the DCE endpoint
// + DCR immutable id from the telemetryExport provisioning module (non-secret ids). Runs as the
// WORKER identity (which holds the least-privilege Monitoring Metrics Publisher grant on the DCR).
// ======================================================================================
module telemetryExportJob 'modules/module-job.bicep' = {
  name: 'job-telemetry_export'
  params: {
    location: location
    environmentId: core.outputs.environmentId
    identityId: core.outputs.identityWorkerId
    identityClientId: core.outputs.identityWorkerClientId
    storageName: core.outputs.storageName
    registry: containerRegistry
    imageTag: imageTag
    moduleName: 'telemetry_export'
    triggerType: 'Schedule'
    cronExpression: '*/5 * * * *'
    queueName: ''
    minExecutions: 0
    maxExecutions: 1
    cpu: '0.25'
    memoryGi: '0.5Gi'
    apiBaseUrl: 'https://${apiApp.outputs.fqdn}'
    // Keyless, non-secret export target ids threaded from the provisioning module's outputs so the
    // exporter opts in at runtime (absent ⇒ the module runs inert). No key/SAS/connection string.
    extraEnv: [
      { name: 'TELEMETRY_EXPORT_DCE_ENDPOINT', value: telemetryExport.outputs.dceLogsIngestionEndpoint }
      { name: 'TELEMETRY_EXPORT_DCR_IMMUTABLE_ID', value: telemetryExport.outputs.dcrImmutableId }
    ]
  }
}

output registryLoginServer string = core.outputs.registryLoginServer
output apiFqdn string = apiApp.outputs.fqdn
output webFqdn string = webApp.outputs.fqdn
// Managed Grafana public endpoint (no secrets). Feed this into the web build-time VITE_GRAFANA_URL
// (the keyless deep-link surface) — Managed Grafana blocks iframing by default, so this raw
// endpoint is NOT an embeddable panel URL. Only set VITE_GRAFANA_PANEL_URL to a separate,
// auth-proxied, embeddable panel URL; never a token in either.
output grafanaEndpoint string = grafana.outputs.grafanaEndpoint

// ---- API-only-writer enforcement surface (issue #79 brownfield fix) ----
// Consumed by the post-deploy CD gate (.github/workflows/release.yml → scripts/
// cleanup_verify_state_writers.py): it lists Blob/Table Data Contributor assignments at
// storageAccountId and asserts the ONLY principals holding them are the api + worker identities,
// removing any legacy shared-identity writer first. Object ids are not credentials (keyless).
output storageAccountId string = core.outputs.storageAccountId
output apiIdentityPrincipalId string = core.outputs.identityApiPrincipalId
output workerIdentityPrincipalId string = core.outputs.identityWorkerPrincipalId
