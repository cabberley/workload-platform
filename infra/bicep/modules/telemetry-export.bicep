// telemetry-export.bicep — provision the emit path for the baseline #58 Grafana boards (issue #86).
//
// Three things, all in-boundary and keyless:
//   1. The FOUR custom Log Analytics tables the boards read — WpNodeState_CL, WpSpof_CL,
//      WpFinding_CL, WpConnectorFetch_CL — with EXACTLY the aggregate, PII-free column schemas
//      documented in infra/grafana/README.md (plus the mandatory TimeGenerated system column).
//   2. A Data Collection Endpoint (DCE) + a Data Collection Rule (DCR) mapping one Custom-<Table>
//      stream per table into the in-boundary workspace via the Logs Ingestion API.
//   3. A LEAST-PRIVILEGE role assignment so the emitting (worker) identity can publish to the DCR:
//      Monitoring Metrics Publisher, scoped to THIS DCR only (guardrail #7). See the rationale
//      inline at the assignment.
//
// Keyless throughout: the module publishes with the worker user-assigned Managed Identity via the
// Logs Ingestion API — no ingestion key, SAS, or connection string exists anywhere. The DCE
// endpoint + DCR immutable id are non-secret ids surfaced as outputs and fed to the telemetry_export
// Job as env (TELEMETRY_EXPORT_DCE_ENDPOINT / TELEMETRY_EXPORT_DCR_IMMUTABLE_ID) by main.bicep.
param location string = resourceGroup().location

@description('Short name prefix for resources (matches core.bicep)')
@minLength(1)
param namePrefix string = 'wp'

@description('Resource token to keep names stable per resource group')
param resourceToken string = uniqueString(resourceGroup().id)

@description('Resource id of the in-boundary Log Analytics workspace (from core.outputs.logAnalyticsId)')
param logAnalyticsId string

@description('Name of the in-boundary Log Analytics workspace (from core.outputs.logAnalyticsName)')
param logAnalyticsName string

@description('Principal (object) id of the worker Managed Identity that publishes telemetry (from core.outputs.identityWorkerPrincipalId, issue #79). It runs the telemetry_export Job.')
param publisherPrincipalId string

// Monitoring Metrics Publisher — the narrowest built-in role that grants data-plane publish rights
// to a Data Collection Rule via the Logs Ingestion API. Verified against the Azure RBAC built-in
// roles reference (Monitor category): 3913510d-42f4-4e42-8a64-420c390055eb.
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

var dceName = take('${namePrefix}-dce-${resourceToken}', 44)
var dcrName = take('${namePrefix}-dcr-telemetry-${resourceToken}', 64)

// Existing in-boundary workspace (created in core.bicep) — parent of the custom tables and the DCR
// destination. Referenced (not created) here so tables/DCR bind to the single in-boundary workspace.
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsName
}

// ---- The four custom (_CL) tables — EXACT aggregate, PII-free schemas the #58 boards read ----
// Every custom table carries the mandatory TimeGenerated (datetime) system column. WpSpof_CL's
// board reads only Workload_s + NodeRef_s, but TimeGenerated is required by Log Analytics (and the
// board filters on the dashboard time range), so it is present here too. NodeRef_s is an OPAQUE node
// ref (domain-separated sha256 in src/modules/telemetry_export/shaping.py) — never a raw resource id.
resource tableNodeState 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'WpNodeState_CL'
  properties: {
    plan: 'Analytics'
    schema: {
      name: 'WpNodeState_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'Workload_s', type: 'string' }
        { name: 'State_s', type: 'string' } // up | degraded | down | unknown
      ]
    }
  }
}

resource tableSpof 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'WpSpof_CL'
  properties: {
    plan: 'Analytics'
    schema: {
      name: 'WpSpof_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'Workload_s', type: 'string' }
        { name: 'NodeRef_s', type: 'string' } // OPAQUE node ref — never a raw resource/node id
      ]
    }
  }
}

resource tableFinding 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'WpFinding_CL'
  properties: {
    plan: 'Analytics'
    schema: {
      name: 'WpFinding_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'Workload_s', type: 'string' }
        { name: 'BlastRadius_d', type: 'real' }
      ]
    }
  }
}

resource tableConnectorFetch 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'WpConnectorFetch_CL'
  properties: {
    plan: 'Analytics'
    schema: {
      name: 'WpConnectorFetch_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'Connector_s', type: 'string' }
        { name: 'Success_b', type: 'boolean' }
      ]
    }
  }
}

// ---- Data Collection Endpoint (public ingestion URI; in-boundary, no secret) ----
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dceName
  location: location
  properties: {
    // Logs ingestion over the endpoint; no key — publishers authenticate with Managed Identity.
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// ---- Data Collection Rule: one Custom-<Table> stream per table → in-boundary workspace ----
// Each streamDeclaration's columns MUST match the shaped record (see exporter.to_la_columns()); the
// dataFlow uses transformKql 'source' (identity) and outputs to the matching _CL table. The stream
// names MUST equal the exporter defaults (Custom-WpNodeState_CL, ...).
resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-WpNodeState_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Workload_s', type: 'string' }
          { name: 'State_s', type: 'string' }
        ]
      }
      'Custom-WpSpof_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Workload_s', type: 'string' }
          { name: 'NodeRef_s', type: 'string' }
        ]
      }
      'Custom-WpFinding_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Workload_s', type: 'string' }
          { name: 'BlastRadius_d', type: 'real' }
        ]
      }
      'Custom-WpConnectorFetch_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Connector_s', type: 'string' }
          { name: 'Success_b', type: 'boolean' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsId
          name: 'inBoundaryWorkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [ 'Custom-WpNodeState_CL' ]
        destinations: [ 'inBoundaryWorkspace' ]
        transformKql: 'source'
        outputStream: 'Custom-WpNodeState_CL'
      }
      {
        streams: [ 'Custom-WpSpof_CL' ]
        destinations: [ 'inBoundaryWorkspace' ]
        transformKql: 'source'
        outputStream: 'Custom-WpSpof_CL'
      }
      {
        streams: [ 'Custom-WpFinding_CL' ]
        destinations: [ 'inBoundaryWorkspace' ]
        transformKql: 'source'
        outputStream: 'Custom-WpFinding_CL'
      }
      {
        streams: [ 'Custom-WpConnectorFetch_CL' ]
        destinations: [ 'inBoundaryWorkspace' ]
        transformKql: 'source'
        outputStream: 'Custom-WpConnectorFetch_CL'
      }
    ]
  }
  // The tables must exist before the DCR's dataFlows reference their output streams.
  dependsOn: [
    tableNodeState
    tableSpof
    tableFinding
    tableConnectorFetch
  ]
}

// ---- Least-privilege publish grant (guardrail #7) ----
// Monitoring Metrics Publisher, scoped to THIS DCR only — the narrowest built-in role that lets the
// worker identity POST rows to the DCR's streams via the Logs Ingestion API. It grants NO read, NO
// workspace/table management, and NO access to any other DCR or resource. It is deliberately NOT a
// broad Contributor/Monitoring Contributor role. This is a distinct principal+scope from the
// grafana data-source identity's READ roles (grafana.bicep) and from the worker's state-store WRITE
// roles (core.bicep) — export publish and state write are separate, least-privilege grants.
resource metricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, publisherPrincipalId, monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalId: publisherPrincipalId
    principalType: 'ServicePrincipal'
  }
}

@description('Logs Ingestion endpoint URI of the Data Collection Endpoint (no secret). Feeds TELEMETRY_EXPORT_DCE_ENDPOINT.')
output dceLogsIngestionEndpoint string = dce.properties.logsIngestion.endpoint

@description('Immutable id of the Data Collection Rule (no secret). Feeds TELEMETRY_EXPORT_DCR_IMMUTABLE_ID.')
output dcrImmutableId string = dcr.properties.immutableId

output dceName string = dce.name
output dcrName string = dcr.name
