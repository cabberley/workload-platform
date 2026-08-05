// core.bicep — shared in-boundary platform for every module:
//   * Azure Container Registry (keyless; images pulled via Managed Identity / AcrPull)
//   * Log Analytics workspace + Container Apps managed environment
//   * Storage account + the KEDA queues the module triggers reference
//   * Per-component user-assigned Managed Identities (issue #79) — one each for the API core, the
//     module worker/job compute, the web front-end, and the Grafana read surface — with roles
//     scoped so ONLY the writers (api + worker/job) hold the state-store WRITE data roles.
//   * Key Vault (runtime secrets by reference — never in code/outputs)
// Everything is keyless via Managed Identity. No keys/connection strings are emitted as outputs.
@description('Azure region')
param location string = resourceGroup().location

@description('Short name prefix for resources')
@minLength(1)
param namePrefix string = 'wp'

@description('Resource token to keep names unique')
param resourceToken string = uniqueString(resourceGroup().id)

@description('Azure Container Registry name (alphanumeric, globally unique, without .azurecr.io)')
param registryName string

@description('Container Registry SKU')
@allowed([ 'Basic', 'Standard', 'Premium' ])
param registrySku string = 'Basic'

@description('Storage queues the module KEDA triggers reference (mirrors src/modules/*/manifest.yaml).')
param queueNames array = [
  'dependency'   // dependency_graph module (azure-queue trigger)
  'assessments'  // quality_checks module (azure-queue trigger)
  'telemetry'    // aiops module (azure-queue trigger)
  'findings'     // alerts module (azure-queue trigger)
]

// ---- Audit/state tamper-resistance knobs (issue #81) ----
// The state Blob container holds the write-once, version-scoped estate/graph/findings/snapshot/
// manifest artifacts written by AzureStateStore (src/shared/state.py). Blob VERSIONING + soft delete
// make an overwrite/delete of those BLOB STATE ARTIFACTS RECOVERABLE, and a time-based immutability
// (WORM) policy makes them UN-deletable/UN-overwritable for the retention window — storage-layer
// tamper-RESISTANCE for the BLOB state store. NOTE: these are BLOB-service controls and do NOT cover
// the Azure-TABLE audit stream (the #59 hash chain is Table-based) — see the audit note above
// stateTableDataContributorApi (~L429). Retention windows are parameterized.
@description('Name of the durable state Blob container (mirrors WORKLOADS_STATE_CONTAINER, default "state").')
@minLength(3)
@maxLength(63)
param stateContainerName string = 'state'

@description('Soft-delete retention (days) for blobs AND containers on the state account — window to recover a deleted/overwritten state artifact.')
@minValue(1)
@maxValue(365)
param stateSoftDeleteRetentionDays int = 7

@description('Time-based immutability (WORM) retention (days) on the state container — an artifact cannot be deleted/overwritten until this elapses. Unlocked so a human can extend/lock it out-of-band.')
@minValue(1)
@maxValue(146000)
param stateImmutabilityRetentionDays int = 7

@description('Manage (create/update) the state container time-based immutability (WORM) policy from IaC. Set FALSE once the policy has been LOCKED out-of-band — Azure rejects any PUT on a LOCKED immutability policy, so leaving this true would break every subsequent deployment (main.bicep always deploys core).')
param manageStateImmutabilityPolicy bool = true

var laName = '${namePrefix}-log-${resourceToken}'
var envName = '${namePrefix}-env-${resourceToken}'
// Per-component user-assigned identities (issue #79). Each ACA app/job runs as ITS OWN identity so
// component-level least privilege is enforced by RBAC, not just by convention. The writers (api +
// worker/job) are the ONLY principals granted the state-store WRITE data roles; the web front-end
// is a reader; the grafana identity is a read-only Azure Monitor data-source principal.
var idApiName = '${namePrefix}-id-api-${resourceToken}'
var idWorkerName = '${namePrefix}-id-worker-${resourceToken}'
var idWebName = '${namePrefix}-id-web-${resourceToken}'
var idGrafanaName = '${namePrefix}-id-grafana-${resourceToken}'
var kvName = take('${namePrefix}kv${resourceToken}', 24)
var saName = take('${namePrefix}st${resourceToken}', 24)

// Built-in role definition ids (keyless RBAC — least privilege). Every GUID below was verified with
// `az role definition list --name "<Role Name>" --query "[0].name"` against the target tenant.
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'                      // AcrPull
var storageQueueDataContributorRoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'  // Storage Queue Data Contributor
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'          // Key Vault Secrets User
// Read-plane roles (issue #80). Reader is a management-plane read role; the storage data roles are
// data-plane. None grants any management-plane write (no Contributor at the control plane).
var readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'                        // Reader
var storageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'    // Storage Blob Data Contributor
var storageTableDataContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'   // Storage Table Data Contributor
// Read-plane monitor roles for the worker identity's Azure Monitor connector (aiops). The Grafana
// data-source identity gets its OWN copies of these two roles in grafana.bicep — a different
// principal, so there is no RoleAssignmentExists conflict (the shared-identity coupling that used to
// forbid re-declaring them here no longer applies now that identities are per-component).
var monitoringReaderRoleId = '43d0d8ad-25c7-4714-9337-8ba259a9fe05'              // Monitoring Reader
var logAnalyticsReaderRoleId = '73c42c96-874c-492b-b04d-ab87d138a893'            // Log Analytics Reader

// ---- Per-component user-assigned managed identities (issue #79) ----
// api    : the single-writer API core.
// worker : ALL module workers (aiops, alerts) and jobs (discovery, quality_checks, reassessments,
//          dependency_graph) — they run modules, so they are writers and hold the read-plane roles
//          their connectors need. Per the issue's "one for the worker/job" guidance this is a single
//          identity whose role set is the UNION of what the module workers/jobs need.
// web    : the read-only front-end — it talks only to the API and gets NO state-store write role.
// grafana: read-only Azure Monitor data-source principal (see grafana.bicep) — no write, no AcrPull.
resource identityApi 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: idApiName
  location: location
}

resource identityWorker 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: idWorkerName
  location: location
}

resource identityWeb 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: idWebName
  location: location
}

resource identityGrafana 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: idGrafanaName
  location: location
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: registryName
  location: location
  sku: { name: registrySku }
  properties: {
    adminUserEnabled: false // keyless: pulls happen via Managed Identity + AcrPull
  }
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
    allowSharedKeyAccess: false // keyless: queue access is via Managed Identity only
    minimumTlsVersion: 'TLS1_2'
  }
}

resource queueService 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource queues 'Microsoft.Storage/storageAccounts/queueServices/queues@2023-05-01' = [for q in queueNames: {
  parent: queueService
  name: q
}]

// ---- Blob service hardening for the state store (issue #81) ----
// VERSIONING + CHANGE FEED + soft delete convert destructive blob operations from irreversible into
// recoverable/audited: an overwrite creates a new VERSION (prior bytes retained), a delete is
// SOFT (recoverable for the retention window), and the change feed is an append-only, out-of-band
// log of every blob mutation. This hardens the BLOB STATE ARTIFACTS (estate/graph/findings/snapshot/
// manifest blobs) and is keyless (no keys/SAS — access stays Managed-Identity only). It does NOT
// protect the Azure-TABLE audit stream — the #59 audit hash chain is Table-based and these
// blob-service controls do not cover Tables (see the audit note above stateTableDataContributorApi).
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    isVersioningEnabled: true                              // overwrite ⇒ new version, prior bytes retained
    changeFeed: { enabled: true }                          // append-only out-of-band log of blob mutations
    deleteRetentionPolicy: {                               // blob soft delete: a deleted blob is recoverable
      enabled: true
      days: stateSoftDeleteRetentionDays
    }
    containerDeleteRetentionPolicy: {                      // container soft delete: a deleted container is recoverable
      enabled: true
      days: stateSoftDeleteRetentionDays
    }
  }
}

// The durable state container, pre-created so a WORM policy can be attached (AzureStateStore also
// create_container_if_not_exists at runtime — idempotent). Name mirrors WORKLOADS_STATE_CONTAINER.
resource stateContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: stateContainerName
  properties: {
    publicAccess: 'None'                                   // in-boundary: never publicly reachable
  }
}

// Time-based immutability (WORM) policy on the state container (issue #81). While in effect, a blob
// cannot be deleted or overwritten until `immutabilityPeriodSinceCreationInDays` elapses — so a
// Contributor-role principal can no longer delete/clobber committed state artifacts out-of-band.
//   * Left UNLOCKED (no `state: 'Locked'`) so a human operator can EXTEND or LOCK it out-of-band per
//     the customer's retention decision — locking is irreversible, so it is deliberately a human
//     step, not baked into IaC (fail-closed by keeping the safer, reversible posture by default).
//   * `allowProtectedAppendWrites: true` keeps APPEND-blob semantics available under the policy —
//     honouring the append-only guardrail and forward-compatible with the documented migration of
//     the audit log to an immutable append-blob container (see docs/adr/0009-...).
//   * GATED on `manageStateImmutabilityPolicy` (default true). Azure REJECTS any PUT (create/update)
//     on a LOCKED time-based immutability policy — you can only EXTEND retention via the dedicated
//     action, never re-PUT (even with identical properties). Because main.bicep ALWAYS deploys core,
//     leaving this resource unconditional would make the FIRST deployment after a human LOCKs the
//     policy fail on this resource. Operational sequence: deploy (unlocked) → operator EXTENDs/LOCKs
//     out-of-band per the retention decision → operator sets manageStateImmutabilityPolicy=false on
//     all SUBSEQUENT deployments so IaC stops managing the now-locked policy. This is a leaf resource
//     (no output/other resource references it), so the conditional cannot break any reference.
resource stateContainerImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = if (manageStateImmutabilityPolicy) {
  parent: stateContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: stateImmutabilityRetentionDays
    allowProtectedAppendWrites: true
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

resource env 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: envName
  location: location
  properties: {
    // Keyless: emit app logs to Azure Monitor and route them to Log Analytics via a diagnostic
    // setting (below). No Log Analytics shared key is read anywhere.
    appLogsConfiguration: {
      destination: 'azure-monitor'
    }
  }
}

resource envDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-log-analytics'
  scope: env
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      { categoryGroup: 'allLogs', enabled: true }
    ]
  }
}

// ======================================================================================
// Keyless, least-privilege role assignments (issue #79 splits write vs read across identities).
// Assignment names are guid(scope, identity, roleId) so they are deterministic and idempotent; each
// per-component identity produces a DISTINCT name for the same role+scope.
//
// Component → identity → roles matrix enforced below:
//   api     (writer) : AcrPull · Queue Data Contributor · KV Secrets User · Blob+Table Data Contributor
//   worker  (writer) : AcrPull · Queue Data Contributor · KV Secrets User · Blob+Table Data Contributor
//                      · Reader (RG) · Monitoring Reader (RG) · Log Analytics Reader (workspace)
//   web     (reader) : AcrPull · KV Secrets User          ← NO storage data role, NO queue role
//   grafana (reader) : Monitoring Reader + Log Analytics Reader (assigned in grafana.bicep)
// The state-store WRITE data roles (Blob/Table Data Contributor) are granted to the api and worker
// identities ONLY. The web identity never receives them, so the "API is the only writer" boundary
// (with the worker/job that runs modules) is enforced by RBAC, not merely by convention.
// ======================================================================================

// ---- AcrPull: each container principal pulls its image without a registry credential ----
resource acrPullApi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identityApi.id, acrPullRoleId)
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: identityApi.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource acrPullWorker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identityWorker.id, acrPullRoleId)
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: identityWorker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource acrPullWeb 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identityWeb.id, acrPullRoleId)
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: identityWeb.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---- Storage Queue Data Contributor: enqueue/dequeue work + KEDA queue-length reads ----
// Only the API (dispatches work onto the queues) and the worker/job compute (module KEDA scalers
// + enqueue/dequeue) authenticate to queues. The web front-end scales on HTTP concurrency only and
// never touches a queue, so it is deliberately NOT granted this role.
resource queueDataContributorApi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityApi.id, storageQueueDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorRoleId)
    principalId: identityApi.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource queueDataContributorWorker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityWorker.id, storageQueueDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorRoleId)
    principalId: identityWorker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---- Key Vault Secrets User: runtime secrets read by identity, never embedded ----
// Granted to the SECRET-CONSUMING container principals ONLY — the api and worker, which resolve
// their own runtime config from Key Vault by reference. Read-only (Secrets User, not Officer). The
// web identity is deliberately excluded: the web component is a static nginx SPA that reads no
// runtime secret from Key Vault (module-app.bicep defines no `secrets`/Key Vault `secretRef`), so
// granting it vault-wide secret read would needlessly widen the blast radius of the public,
// internet-facing frontend (least-privilege, guardrail #7). The grafana identity reads no Key Vault.
resource kvSecretsUserApi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identityApi.id, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: identityApi.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource kvSecretsUserWorker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identityWorker.id, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: identityWorker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---- Read-plane role assignments (issue #80 intent preserved, now scoped to the WORKER only) ----
// The read-plane clients (ARG discovery, network topology, the aiops Azure Monitor connector) all
// run inside the worker/job compute, so these grants move from the old shared identity to the
// worker identity. The web and grafana identities do NOT receive them (grafana gets its own
// monitor-read pair in grafana.bicep). The worker identity's effective set is the UNION of what the
// module workers/jobs need — the issue explicitly sanctions "one for the worker/job".

// Reader (management-plane */read). Consumers (all worker/job compute):
//   * Azure Resource Graph discovery — src/modules/discovery/arg.py (AzureResourceGraphClient):
//     read-only KQL over resources (id/name/type/tags). ACTIVE — the discovery Job runs today.
//   * Network-topology reads — src/modules/dependency_graph/topology.py
//     (AzureNetworkTopologyClient): load balancers / application gateways / network interfaces
//     read. FORWARD-LOOKING — injected via ctx.clients["network"] but not yet wired into the
//     deployed job's env; provisioning its least-privilege role now keeps it fail-closed.
// Reader also transitively covers the Azure Monitor connector's in-RG reads: */read includes
// Microsoft.Insights/*/read (metrics) and Microsoft.OperationalInsights/workspaces/query/*/read
// (Log Analytics); explicit Monitoring Reader + Log Analytics Reader for that connector are ALSO
// granted to the worker below (a distinct principal from the grafana identity, so no conflict).
//
// SCOPE — this is a resourceGroup-scoped deployment (main.bicep targetScope = 'resourceGroup'), so
// Reader is assigned at the RESOURCE GROUP: the narrowest scope this template can grant inline. ARG
// discovery reads across the SUBSCRIPTION, so subscription-wide discovery additionally requires a
// SUBSCRIPTION-scope Reader applied SEPARATELY (it cannot be created from an RG-scoped deployment).
// At this RG scope, ARG returns only the in-boundary resources in this resource group.
resource readerWorker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, identityWorker.id, readerRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', readerRoleId)
    principalId: identityWorker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Monitoring Reader (RG scope) — the aiops Azure Monitor connector's metrics edge
// (src/modules/aiops/connectors/azure_monitor.py). Metrics span multiple platform resources
// (Container Apps, storage), so RG is the narrowest scope that resolves every metric. The grafana
// data-source identity holds its OWN Monitoring Reader (grafana.bicep) — a different principal.
resource monitoringReaderWorker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, identityWorker.id, monitoringReaderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringReaderRoleId)
    principalId: identityWorker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Log Analytics Reader (workspace scope) — the aiops connector's logs edge
// (LogsQueryClient.query_workspace) reads only the single in-boundary workspace, so the grant is
// scoped to that workspace resource (least privilege), not the RG. The grafana data-source identity
// holds its OWN workspace-scoped Log Analytics Reader (grafana.bicep) — a different principal.
resource logAnalyticsReaderWorker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logAnalytics.id, identityWorker.id, logAnalyticsReaderRoleId)
  scope: logAnalytics
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', logAnalyticsReaderRoleId)
    principalId: identityWorker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---- State-store WRITE data roles (the API-only-writer boundary) — api + worker ONLY ----
// Consumer: the Azure state backend — src/shared/state.py (AzureStateStore). It creates the
// snapshots/workloads tables and writes the manifest entities that are its single commit point
// (create_table_if_not_exists / create_entity / update_entity), and creates the state container +
// uploads/reads the immutable version-scoped estate/graph/findings blobs (create_container /
// upload_blob / download_blob). Because it WRITES, the Contributor data roles are required, not the
// read-only *Data Reader variants (Contributor ⊇ Reader). FORWARD-LOOKING: the backend defaults to
// local and is selected only when WORKLOADS_STATE_BACKEND=azure with the state endpoints wired.
//
// These are granted to the api (the single writer) and the worker/job (which runs modules) ONLY.
// The web (reader) identity is deliberately absent from these four assignments, so the web front-end
// CANNOT write blobs or tables — the least-privilege boundary this issue enforces. Scoped to the
// storage account (narrowest inline scope); allowSharedKeyAccess is false, so access is keyless.
//
// TABLE AUDIT STORE DESTRUCTIVE PERMISSIONS (issue #81) — why they are NOT restricted, this stays
// Table Data Contributor, and NOT a narrower/custom append-only role:
//   * The audit log is Azure-TABLE-based (AzureStateStore.append_audit, _AZ_AUDIT_TABLE). Azure
//     Table Storage has NO built-in append-only data role, and its RBAC data actions
//     (Microsoft.Storage/storageAccounts/tableServices/tables/entities/{read,write,add,update,
//     delete}/action) CANNOT be scoped to an individual table by name — a custom role can only
//     grant/deny an action across ALL tables on the account.
//   * The single-writer commit path LEGITIMATELY needs entity update/merge on OTHER tables: the
//     manifest commit point (workloads table, update_entity replace) and the snapshot pointer
//     (snapshots table, update_entity merge). A role that denied entities/delete + entities/write
//     to protect the audit table would therefore ALSO break those non-audit writes.
//   * Conclusion: a truly append-only Table role is NOT expressible without breaking the writer.
//     IMPORTANT — the blob-service controls above (versioning, change feed, blob/container soft
//     delete, and the container WORM immutability policy) are BLOB-service controls scoped to the
//     blob state CONTAINER: they protect the blob STATE artifacts (estate/graph/findings/snapshot/
//     manifest blobs) and provide NO storage-layer tamper-resistance to Azure TABLE entities. The
//     audit stream is a TABLE and the destructive Table role (Table Data Contributor) is UNCHANGED,
//     so a principal holding it can still replace/delete audit event entities and advance the HEAD
//     out-of-band. Table audit tamper-resistance TODAY therefore comes ONLY from (a) the
//     application-level create-only + ETag-guarded append path (append_audit exposes no rewrite
//     path) and (c) the documented migration of the audit log to an immutable append-blob container
//     — which remains the REQUIRED (still-unresolved) path to genuine per-store audit WORM PRECISELY
//     because the blob-service/WORM posture (b) does not cover Tables (see
//     docs/adr/0009-audit-store-tamper-resistance.md). Because no role id changes, the CD gate
//     scripts/cleanup_verify_state_writers.py (STATE_WRITE_ROLE_IDS) is intentionally UNCHANGED.
resource stateTableDataContributorApi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityApi.id, storageTableDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorRoleId)
    principalId: identityApi.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource stateTableDataContributorWorker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityWorker.id, storageTableDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorRoleId)
    principalId: identityWorker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource stateBlobDataContributorApi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityApi.id, storageBlobDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorRoleId)
    principalId: identityApi.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource stateBlobDataContributorWorker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityWorker.id, storageBlobDataContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorRoleId)
    principalId: identityWorker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

output environmentId string = env.id
// Per-component identity outputs (issue #79). main.bicep threads each component's OWN identity into
// its ACA app/job; grafana.bicep receives the read-only grafana identity.
output identityApiId string = identityApi.id
output identityApiClientId string = identityApi.properties.clientId
// Principal (object) ids of the two WRITER identities — surfaced so the post-deploy CD gate can
// assert that ONLY these principals hold Blob/Table Data Contributor at the storage-account scope
// (issue #79 brownfield fix). No secrets: an object id is not a credential.
output identityApiPrincipalId string = identityApi.properties.principalId
output identityWorkerId string = identityWorker.id
output identityWorkerClientId string = identityWorker.properties.clientId
output identityWorkerPrincipalId string = identityWorker.properties.principalId
output identityWebId string = identityWeb.id
output identityWebClientId string = identityWeb.properties.clientId
output identityGrafanaId string = identityGrafana.id
output identityGrafanaPrincipalId string = identityGrafana.properties.principalId
output storageName string = storage.name
// Storage-account resource id — the SCOPE the post-deploy CD gate lists state-write role
// assignments against to enforce the API-only-writer boundary (issue #79 brownfield fix).
output storageAccountId string = storage.id
output keyVaultName string = keyVault.name
// Key Vault resource URI (a non-secret URL, e.g. https://<vault>.vault.azure.net). Threaded to the
// container apps as the non-secret ``$WP_KEY_VAULT_URI`` and used to build Key Vault-backed
// ``secretRef`` references so runtime secrets are read BY identity, never as plaintext (issue #85).
output keyVaultUri string = keyVault.properties.vaultUri
output logAnalyticsId string = logAnalytics.id
output logAnalyticsName string = logAnalytics.name
output registryName string = registry.name
output registryLoginServer string = registry.properties.loginServer
