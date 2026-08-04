// grafana.bicep — Azure Managed Grafana as the telemetry visualization surface (issue #58, ADR
// 0007). Keyless by construction:
//   * The instance authenticates to its Azure Monitor data source with a DEDICATED read-only
//     user-assigned Managed Identity created in core.bicep (identityGrafana, issue #79) — no Grafana
//     API keys, no service-principal secrets. This identity is the DATA-SOURCE (read) identity ONLY
//     and, unlike the api/worker identities, holds NO state-store write role (it can never write).
//   * `apiKey: 'Disabled'` so no admin API keys can be issued for the instance.
//   * Dashboards + the Azure Monitor data source are provisioned separately via the Grafana API
//     (see infra/grafana/README.md) by a SEPARATE Entra caller (CI Managed Identity or operator)
//     holding the Grafana Editor data-plane role — NOT this shared identity, which never provisions
//     content and holds no Grafana Editor/Admin role. They are NOT child resources here, and no
//     board JSON, workspace id, subscription id or token is embedded in this template.
//
// Least privilege: the dedicated grafana identity is granted ONLY read roles required by the Azure
// Monitor data source — Monitoring Reader (metrics + the resources' monitoring config) and Log Analytics
// Reader (KQL over the in-boundary workspace). No write/admin (e.g. Grafana Admin, Monitoring
// Contributor) role is granted. See the role-assignment comments below for the scope rationale.
param location string = resourceGroup().location

@description('Short name prefix for resources (matches core.bicep)')
@minLength(1)
param namePrefix string = 'wp'

@description('Resource token to keep the globally-unique Grafana name stable per resource group')
param resourceToken string = uniqueString(resourceGroup().id)

@description('Resource id of the dedicated read-only Grafana user-assigned Managed Identity (from core.outputs.identityGrafanaId, issue #79)')
param identityResourceId string

@description('Principal (object) id of that identity (from core.outputs.identityGrafanaPrincipalId) — the RBAC target')
param identityPrincipalId string

@description('Name of the in-boundary Log Analytics workspace (from core.outputs.logAnalyticsName). Used to scope the Log Analytics Reader assignment to that single workspace — least privilege.')
param logAnalyticsName string

@description('Grafana SKU. Standard is the only GA tier.')
@allowed([ 'Standard' ])
param grafanaSku string = 'Standard'

var grafanaName = take('${namePrefix}-grafana-${resourceToken}', 23)

// Built-in role definition ids (least-privilege READ roles for the Azure Monitor data source).
// Verified against the Azure RBAC built-in-roles reference (Monitor category):
//   Monitoring Reader   43d0d8ad-25c7-4714-9337-8ba259a9fe05
//   Log Analytics Reader 73c42c96-874c-492b-b04d-ab87d138a893
var monitoringReaderRoleId = '43d0d8ad-25c7-4714-9337-8ba259a9fe05'  // Monitoring Reader
var logAnalyticsReaderRoleId = '73c42c96-874c-492b-b04d-ab87d138a893' // Log Analytics Reader

resource grafana 'Microsoft.Dashboard/grafana@2023-09-01' = {
  name: grafanaName
  location: location
  sku: {
    name: grafanaSku
  }
  // Keyless: use the dedicated read-only grafana user-assigned identity (issue #79) so the Azure
  // Monitor data source authenticates as a workload identity — no keys, and no write role.
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityResourceId}': {}
    }
  }
  properties: {
    // No Grafana API keys / service-account tokens are issued for the instance (keyless).
    apiKey: 'Disabled'
    // Public endpoint reachable in-boundary. This raw endpoint is the value for the console's
    // VITE_GRAFANA_URL (keyless Entra-SSO DEEP-LINK) — it is NOT a framable/embeddable panel URL:
    // Managed Grafana blocks iframing by default, so any iframe path needs a SEPARATE reverse proxy.
    // Tighten to Private with a private endpoint if the deployment requires it (out of scope for #58).
    publicNetworkAccess: 'Enabled'
    grafanaIntegrations: {
      // The built-in Azure Monitor data source references the shared user-assigned identity above
      // for READ QUERIES ONLY; it is configured post-provision via the Grafana API by a SEPARATE
      // Entra caller holding Grafana Editor (NOT this identity — see infra/grafana/README.md). No
      // data source secrets live in IaC.
      azureMonitorWorkspaceIntegrations: []
    }
  }
}

// Existing in-boundary Log Analytics workspace (created in core.bicep). Referenced here ONLY so the
// Log Analytics Reader assignment below can be scoped to this single workspace (least privilege),
// rather than the whole resource group.
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsName
}

// ---- Least-privilege READ role assignments for the shared identity ----
// Two roles, deliberately scoped DIFFERENTLY to stay least-privilege:
//   * Monitoring Reader — RESOURCE GROUP scope. Metrics span MULTIPLE platform resources (Container
//     Apps, storage, and the customer workload signals surfaced to Azure Monitor), not just the
//     workspace, so RG is the narrowest scope that still lets the data source resolve every metric
//     the baseline boards query. It grants NO access outside this RG and NO write/admin anywhere.
//   * Log Analytics Reader — WORKSPACE scope. The log-backed panels (and the Azure Monitor
//     connector's logs edge, LogsQueryClient.query_workspace) read only the SINGLE in-boundary
//     workspace, so the assignment is scoped to that workspace resource — not the RG — so it grants
//     query access to NO other workspace that may exist in the RG.
// If boards ever need a workspace in another RG, add a second, explicitly-scoped assignment rather
// than widening either of these.

// Monitoring Reader: read metrics and the monitoring configuration of resources in this RG.
resource monitoringReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, identityPrincipalId, monitoringReaderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringReaderRoleId)
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Log Analytics Reader: run KQL (read-only) over the in-boundary Log Analytics workspace for the
// log-backed panels. Scoped to the workspace resource (least privilege) — the guid() seed includes
// the workspace id so this is a distinct, idempotent assignment. Read-only — it cannot modify
// data-collection or workspace settings.
resource logAnalyticsReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logAnalytics.id, identityPrincipalId, logAnalyticsReaderRoleId)
  scope: logAnalytics
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', logAnalyticsReaderRoleId)
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

@description('Public endpoint of the Managed Grafana instance (no secrets).')
output grafanaEndpoint string = grafana.properties.endpoint
output grafanaName string = grafana.name
