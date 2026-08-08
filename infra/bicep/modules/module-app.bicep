// module-app.bicep — deploy a `kind: service` module as its OWN Azure Container App with its OWN
// KEDA scale rule(s). One of these per service module => modules scale independently.
//
// Scale triggers are expressed declaratively (queue / cpu / http) and assembled here so keyless
// azure-queue scaling authenticates with the user-assigned Managed Identity (api-version
// 2025-01-01 supports scale-rule identity). No connection strings or keys anywhere.
param location string
param environmentId string
param identityId string
param identityClientId string
param registry string
param imageTag string

@description('Module name, e.g. aiops')
param moduleName string
param image string
param minReplicas int = 1
param maxReplicas int = 10
param cpu string = '0.5'
param memoryGi string = '1.0Gi'

@description('Container command override (e.g. the service entrypoint). Empty => use image default.')
param command array = []

@description('Storage account name backing keyless azure-queue KEDA scalers')
param storageName string = ''

@description('azure-queue KEDA trigger: queue name ("" = none). queueLength uses KEDA default (5).')
param queueName string = ''

@description('cpu KEDA trigger: target Utilization percent (0 = none)')
param cpuUtilization int = 0

@description('http KEDA trigger: concurrent requests per replica (0 = none)')
param httpConcurrency int = 0

@description('Extra env vars')
param envVars array = []

@description('Key Vault resource URI (e.g. https://<vault>.vault.azure.net) backing secretRefs. Empty => no Key Vault-backed secrets and no WP_KEY_VAULT_URI injected.')
param keyVaultUri string = ''

@description('Key Vault-backed secrets to inject by identity (issue #85). Each item: { secretRefName, secretName, envVar } — a container secret named secretRefName sourced from keyVaultUri/secrets/secretName, surfaced to the app as env var envVar via secretRef. Never a plaintext value here.')
param keyVaultSecrets array = []

@description('Entra auth mode for the API (issue #64): "required" (fail-closed default — the API refuses to serve unless authTenantId + authAudience are set), or "disabled" (deliberate no-auth). Empty => not injected (only the API core needs it). Non-secret.')
param authMode string = ''

@description('Entra tenant (directory) id the API validates tokens against (issue #64). Non-secret identifier. Empty => not injected.')
param authTenantId string = ''

@description('Expected token audience — the API app registration Application ID URI / client id (issue #64). Non-secret. Empty => not injected.')
param authAudience string = ''

@description('Whether this app gets PUBLIC (external) Container Apps ingress. Only meaningful for the web app; the API is ALWAYS internal. review-67-v4 invariant: the public web front door is opened ONLY when the platform enforces required auth — main.bicep sets this to (authMode == required). Default false => internal-only (fail-closed, zero public surface).')
param ingressExternal bool = false

// Assemble this module's KEDA scale rules from its declared triggers (keyless queue auth via MI).
var queueRules = empty(queueName) ? [] : [
  {
    name: 'queue-${queueName}'
    custom: {
      type: 'azure-queue'
      identity: identityId
      metadata: {
        accountName: storageName
        queueName: queueName
        cloud: 'AzurePublicCloud'
      }
    }
  }
]
var cpuRules = cpuUtilization == 0 ? [] : [
  {
    name: 'cpu'
    custom: {
      type: 'cpu'
      metadata: {
        type: 'Utilization'
        value: string(cpuUtilization)
      }
    }
  }
]
var httpRules = httpConcurrency == 0 ? [] : [
  {
    name: 'http'
    http: {
      metadata: {
        concurrentRequests: string(httpConcurrency)
      }
    }
  }
]
var scaleRules = concat(queueRules, cpuRules, httpRules)

// Key Vault-backed secrets (issue #85). Each declared secret becomes a container-app `secret` that
// ACA resolves from Key Vault BY the app's user-assigned Managed Identity (keyless — no plaintext
// value in the template), exposed to the container as an env var via `secretRef`. This is what
// finally EXERCISES the `Key Vault Secrets User` role granted in core.bicep. When `keyVaultUri` is
// set we also inject the non-secret `WP_KEY_VAULT_URI` so the app-side provider (shared/secret_provider.py)
// can additionally resolve required secrets by identity at composition time (fail closed).
var kvSecrets = [for s in keyVaultSecrets: {
  name: s.secretRefName
  keyVaultUrl: '${keyVaultUri}/secrets/${s.secretName}'
  identity: identityId
}]
var kvSecretEnv = [for s in keyVaultSecrets: {
  name: s.envVar
  secretRef: s.secretRefName
}]
var kvUriEnv = empty(keyVaultUri) ? [] : [
  { name: 'WP_KEY_VAULT_URI', value: keyVaultUri }
]

// Entra auth config (issue #64), keyless — non-secret identifiers only, injected per-var when set.
// The API core reads WP_AUTH_MODE (default fail-closed `required` in main.bicep) + tenant + audience
// and enforces token validation on every state-mutating request; a missing var no longer means
// "no auth" (the app's startup guard refuses to serve when required-but-unconfigured).
var authModeEnv = empty(authMode) ? [] : [
  { name: 'WP_AUTH_MODE', value: authMode }
]
var authTenantEnv = empty(authTenantId) ? [] : [
  { name: 'WP_AUTH_TENANT_ID', value: authTenantId }
]
var authAudienceEnv = empty(authAudience) ? [] : [
  { name: 'WP_AUTH_AUDIENCE', value: authAudience }
]
var authEnv = concat(authModeEnv, authTenantEnv, authAudienceEnv)

// Azure RESOURCE NAMES (Microsoft.App/containerApps, and the container label below) allow only
// lowercase alphanumerics and hyphens — an underscore makes `az deployment` fail. Hyphenate the
// module id for the Azure name ONLY; the real module identity (WP_MODULE env below) keeps the
// underscore so the worker dispatches on the true module name.
var resourceName = replace(moduleName, '_', '-')

resource app 'Microsoft.App/containerApps@2025-01-01' = {
  name: 'wp-${resourceName}'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identityId}': {} }
  }
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      activeRevisionsMode: 'Single'
      // Key Vault-backed secrets resolved by the app identity (empty => none). Never plaintext.
      secrets: kvSecrets
      registries: [
        { server: '${registry}.azurecr.io', identity: identityId }
      ]
      // The API is ALWAYS internal (external: false). The web app is external ONLY when
      // ingressExternal is true — main.bicep couples that to authMode == 'required' so the public
      // web front door can never be open while the API is unauthenticated (review-67-v4).
      ingress: moduleName == 'api' || moduleName == 'web' ? {
        external: moduleName == 'web' ? ingressExternal : false
        targetPort: moduleName == 'api' ? 8000 : 80
        transport: 'auto'
      } : null
    }
    template: {
      containers: [
        {
          name: resourceName
          image: '${registry}.azurecr.io/workloads-platform/${image}:${imageTag}'
          command: empty(command) ? null : command
          resources: { cpu: json(cpu), memory: memoryGi }
          env: concat([
            { name: 'AZURE_CLIENT_ID', value: identityClientId }
            { name: 'WP_MODULE', value: moduleName }
          ], kvUriEnv, kvSecretEnv, authEnv, envVars)
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: scaleRules
      }
    }
  }
}

output fqdn string = moduleName == 'api' || moduleName == 'web' ? app.properties.configuration.ingress.fqdn : ''
