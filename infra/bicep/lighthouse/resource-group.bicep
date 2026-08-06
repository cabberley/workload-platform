// resource-group.bicep — Azure Lighthouse delegated resource management, RESOURCE-GROUP scope.
//
// Same as subscription.bicep, but delegates ONLY a single named resource group instead of the whole
// subscription — the NARROWEST delegation scope (least privilege, guardrail #7). Use this when the
// MSP only needs to observe one in-boundary workload resource group rather than the entire estate.
//
// THE CUSTOMER deploys this at SUBSCRIPTION scope (`az deployment sub create`) because the
// registrationDefinition is a subscription-level resource; the registrationAssignment is projected
// DOWN to the target resource group via the nested `registration-assignment` module. Everything
// else — keyless identity projection, read-only least-privilege roles, per-customer boundary
// preservation (no bulk copy/export of workload data; the Reader telemetry-read residual of
// ADR-0011 Option B applies here too) — is identical to the subscription-scope variant.
targetScope = 'subscription'

@description('MSP offer name shown to the customer in Service providers > Service provider offers.')
@minLength(3)
@maxLength(120)
param mspOfferName string = 'Aegis Workloads Platform — delegated observability (RG-scoped)'

@description('Human-readable description of what the MSP delegation grants and why.')
param mspOfferDescription string = 'Least-privilege, read-only ARM control-plane access via the built-in Reader role for the Aegis Workloads Platform to discover and observe a single resource group. Reader\'s read scope includes telemetry reads (metric values, Log Analytics query results); this residual is accepted under ADR-0011 Option B and audited via the customer\'s Log Analytics query audit logs (LAQueryLogs) — metric reads are not individually auditable. The delegation copies/exports no workload data.'

@description('MSP (managing) tenant id — the Entra tenant that will manage the delegated resource group. Maps to the Lighthouse managedByTenantId. Provide the real GUID at deploy time; never hardcode it here.')
param managedByTenantId string

@description('Name of the EXISTING customer resource group to delegate. The delegation applies to this RG only — resources in every other RG in the subscription remain undelegated.')
param delegatedResourceGroupName string

@description('Object id of the MSP Entra principal (recommended: an Entra GROUP) that receives the read-only delegation. Membership is managed MSP-side without re-onboarding. This is the ONLY identity input — roles are fixed by the internal allowlist, not supplied here.')
param principalId string

@description('Display name for the delegated MSP principal, shown in the customer\'s Service provider offers blade.')
param principalIdDisplayName string = 'Aegis Platform Operators (read-only)'

// FIXED, HARDCODED read-only allowlist (guardrail #7, fail-closed). The delegation can grant ONLY
// these built-in role definition GUIDs — they are not overridable at deploy time.
//   * Reader (acdd72a7-3385-48ef-bd42-f606fba81ae7) — built-in, read-only `*/read` over the estate:
//     resource discovery (ARG / resource metadata) AND reading monitor resource *definitions*
//     (alert rules, action groups, diagnostic settings) at the ARM control plane. HONEST SCOPE
//     (ADR-0011 Option B): `*/read` ALSO permits reading metric values and Log Analytics query
//     RESULTS, so the delegated MSP principal CAN read customer telemetry. This telemetry-read
//     residual is knowingly ACCEPTED and compensated by AUDITING (Log Analytics queries via the
//     workspace `LAQueryLogs` audit category; Activity Log catches only administrative writes, not
//     reads; metric-value reads are not individually auditable — an accepted, unmonitored residual —
//     see docs/delivery/lighthouse-onboarding.md), NOT by role scoping — we do not claim telemetry
//     isolation here. We still deliberately do NOT broaden to the separate Monitoring Reader role,
//     which adds further data-plane monitoring actions; least privilege is preserved at "Reader only".
var approvedRoleDefinitionIds = [
  'acdd72a7-3385-48ef-bd42-f606fba81ae7' // Reader (built-in, read-only)
]

// Authorizations are BUILT here by mapping the fixed allowlist onto the single supplied principal —
// never taken as a raw array parameter. This is what makes the delegation fail-closed.
var authorizations = [for roleDefinitionId in approvedRoleDefinitionIds: {
  principalId: principalId
  principalIdDisplayName: principalIdDisplayName
  roleDefinitionId: roleDefinitionId
}]

// eligibleAuthorizations (PIM / just-in-time elevation) are intentionally NOT emitted. Eligible/PIM
// access requires a `justInTimeAccessPolicy` and approver policy sign-off (TODO(human)); until that
// is approved, no eligible authorizations are granted so nothing privileged is ever available JIT.

// Deterministic, idempotent names derived from the offer + subscription + target RG.
var registrationDefinitionName = guid(mspOfferName, subscription().subscriptionId, delegatedResourceGroupName)
var registrationAssignmentName = guid(mspOfferName, subscription().subscriptionId, delegatedResourceGroupName, 'assignment')

// registrationDefinition — subscription-level; declares the offer + least-privilege authorizations
// built internally from the read-only allowlist above.
resource registrationDefinition 'Microsoft.ManagedServices/registrationDefinitions@2022-10-01' = {
  name: registrationDefinitionName
  properties: {
    registrationDefinitionName: mspOfferName
    description: mspOfferDescription
    managedByTenantId: managedByTenantId
    authorizations: authorizations
  }
}

// registrationAssignment — projected DOWN to the single target resource group via a nested module
// (a registrationAssignment must be created AT the scope it delegates).
module registrationAssignment 'modules/registration-assignment.bicep' = {
  name: 'lighthouse-rg-assignment'
  scope: resourceGroup(delegatedResourceGroupName)
  params: {
    assignmentName: registrationAssignmentName
    registrationDefinitionId: registrationDefinition.id
  }
}

// Non-secret outputs for auditing/verification (object ids and resource ids are NOT credentials).
output registrationDefinitionId string = registrationDefinition.id
output delegatedResourceGroupName string = delegatedResourceGroupName
output mspOfferDisplayName string = mspOfferName
