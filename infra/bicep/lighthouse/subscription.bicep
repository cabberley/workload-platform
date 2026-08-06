// subscription.bicep — Azure Lighthouse delegated resource management, SUBSCRIPTION scope.
//
// THE CUSTOMER deploys this into THEIR OWN subscription (`az deployment sub create`) to grant the
// MSP's managing tenant scoped, read-only ARM control-plane access over the WHOLE subscription. The
// customer's deployment stays CUSTOMER-OWNED (issue #66): Lighthouse projects the MSP principal into
// the customer tenant with the least-privilege role below (built-in Reader). Lighthouse itself does
// NOT move or copy any customer data; it grants only scoped ARM reads. NOTE (ADR-0011 Option B):
// Reader's `*/read` can include reading metric values and Log Analytics query results, so the MSP
// principal CAN read customer telemetry. That telemetry-read residual is knowingly ACCEPTED and
// compensated by AUDITING — Log Analytics queries via the workspace `LAQueryLogs` audit category,
// and Activity Log for any (forbidden) administrative write; note Activity Log does NOT log reads,
// and metric-value reads are not individually auditable (an accepted, unmonitored residual). See
// docs/delivery/lighthouse-onboarding.md. This is not compensated by role scoping.
//
// KEYLESS BY CONSTRUCTION: a Lighthouse delegation is pure Entra identity projection. There is NO
// key, secret, SAS, connection string, or credential anywhere in this template, its parameters, or
// its outputs — the MSP principal authenticates from its own tenant with its own Managed Identity.
//
// FAIL-CLOSED LEAST PRIVILEGE (guardrail #7): the delegated `authorizations` are NOT a free-form
// deploy-time parameter. They are constructed INTERNALLY from the hardcoded read-only allowlist
// `approvedRoleDefinitionIds` below (Reader only). A deployer can therefore supply only the MSP
// PRINCIPAL identity — never a role — so Owner / Contributor / User Access Administrator (or any
// other write-capable role) CANNOT be injected. This platform only READS.
targetScope = 'subscription'

@description('MSP offer name shown to the customer in Service providers > Service provider offers.')
@minLength(3)
@maxLength(120)
param mspOfferName string = 'Aegis Workloads Platform — delegated observability'

@description('Human-readable description of what the MSP delegation grants and why.')
param mspOfferDescription string = 'Least-privilege, read-only ARM control-plane access via the built-in Reader role for the Aegis Workloads Platform to discover and observe this subscription. Reader\'s read scope includes telemetry reads (metric values, Log Analytics query results); this residual is accepted under ADR-0011 Option B and audited via the customer\'s Log Analytics query audit logs (LAQueryLogs) — metric reads are not individually auditable. The delegation copies/exports no workload data.'

@description('MSP (managing) tenant id — the Entra tenant that will manage this subscription. Maps to the Lighthouse managedByTenantId. Provide the real GUID at deploy time; never hardcode it here.')
param managedByTenantId string

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

// Deterministic, idempotent names derived from the offer + subscription (no customer identifier is
// hardcoded; re-deploying with the same inputs updates in place).
var registrationDefinitionName = guid(mspOfferName, subscription().subscriptionId)
var registrationAssignmentName = guid(mspOfferName, subscription().subscriptionId, 'assignment')

// registrationDefinition — declares the offer: which tenant manages this scope, and with which
// least-privilege (read-only) roles, built internally from the allowlist above.
resource registrationDefinition 'Microsoft.ManagedServices/registrationDefinitions@2022-10-01' = {
  name: registrationDefinitionName
  properties: {
    registrationDefinitionName: mspOfferName
    description: mspOfferDescription
    managedByTenantId: managedByTenantId
    authorizations: authorizations
  }
}

// registrationAssignment — applies the delegation to THIS subscription (the deployment scope).
resource registrationAssignment 'Microsoft.ManagedServices/registrationAssignments@2022-10-01' = {
  name: registrationAssignmentName
  properties: {
    registrationDefinitionId: registrationDefinition.id
  }
}

// Non-secret outputs for auditing/verification (object ids and resource ids are NOT credentials).
output registrationDefinitionId string = registrationDefinition.id
output registrationAssignmentId string = registrationAssignment.id
output mspOfferDisplayName string = mspOfferName
