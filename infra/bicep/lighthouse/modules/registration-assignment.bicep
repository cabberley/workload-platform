// registration-assignment.bicep — RG-scoped Lighthouse assignment (nested module).
//
// Used by ../resource-group.bicep to project a subscription-level registrationDefinition DOWN onto a
// single resource group. A registrationAssignment must be created AT the scope it delegates, so this
// module runs at resourceGroup scope while its parent runs at subscription scope. Keyless and
// data-free: it carries only the definition's resource id (not a credential).
targetScope = 'resourceGroup'

@description('Deterministic assignment name (a GUID) computed by the parent template.')
param assignmentName string

@description('Resource id of the registrationDefinition to apply to this resource group.')
param registrationDefinitionId string

resource registrationAssignment 'Microsoft.ManagedServices/registrationAssignments@2022-10-01' = {
  name: assignmentName
  properties: {
    registrationDefinitionId: registrationDefinitionId
  }
}

output registrationAssignmentId string = registrationAssignment.id
