# 0012. Key Vault secret injection for runtime config / connector tokens (keyless, fail-closed)

Date: 2026-08-05 · Status: accepted

## Context

Runtime configuration and connector bearer tokens — the flagship example being the System Pulse
read token (`$SYSTEM_PULSE_READ_TOKEN`) — were read **directly from environment variables** at
composition time ([`cli/wiring.py`](../../src/cli/wiring.py),
[`shared/connectors/base.py`](../../src/shared/connectors/base.py)). No Key Vault secret injection
was wired and the Bicep set **no** `secretRef`: `module-app.bicep` declared only plain `env` values
([`infra/bicep/modules/module-app.bicep`](../../infra/bicep/modules/module-app.bicep)). The
**Key Vault Secrets User** role assignment (on the `api`/`worker` identities) existed in
[`core.bicep`](../../infra/bicep/modules/core.bicep) but was **provisioned-but-unused** — nothing
consumed a secret from Key Vault.

This violates the **keyless** guardrail in spirit: while no *long-lived key* was in code, a runtime
secret's *value* still had to be injected as a plaintext env var by the operator/CI rather than read
by the platform's Managed Identity from a vault. It also left a granted RBAC role dormant.

## Decision

**Runtime secrets are resolved from Azure Key Vault BY the platform's Managed Identity at
composition time, with the environment variable kept only as a documented local-development
fallback. Resolution is fail-closed.**

1. **A single Key Vault secret provider.** New [`shared/secret_provider.py`](../../src/shared/secret_provider.py)
   adds `KeyVaultSecretProvider`, which resolves a named secret from a vault using
   `DefaultAzureCredential` (Managed Identity in Azure; the standard credential chain locally) via
   the official `azure-keyvault-secrets` + `azure-identity` SDKs. The Azure imports are **guarded
   and lazy** (inside a method), so importing the module needs no Azure SDK and `mypy src` /
   unit tests stay Azure-free. A `SecretClient`-shaped client is injectable for tests (the SDK is
   mocked — never a real vault). `azure-keyvault-secrets>=4.8` is added to `pyproject.toml`.

2. **Resolution policy — Key Vault first, env fallback only when no vault is configured.**
   `build_secret_provider` returns a provider **only** when `$WP_KEY_VAULT_URI` (a non-secret
   vault URL) is set; otherwise `None`. `resolve_secret(provider, secret_name, env_var, ...)`
   resolves the Key Vault secret by identity when a vault is configured, and reads the env var
   **only** when no vault is configured — preserving existing local/CI workflows unchanged.

3. **Wired into composition and the connector edge.** The composition root
   ([`cli/wiring.py`](../../src/cli/wiring.py)) builds the provider once and injects it into the
   System Pulse connector, whose config now carries the Key Vault secret **name**
   (`system-pulse-read-token`) and whose edge resolves the token through the provider. The shared
   `resolve_bearer_token` ([`shared/connectors/base.py`](../../src/shared/connectors/base.py)) gained
   an optional `secret_provider`/`secret_name` seam: order is injected Managed-Identity token →
   Key Vault secret (authoritative, fail-closed) → local-dev env var. The seam is a structural
   `SecretProvider` Protocol, so the connectors stay free of any Azure SDK.

4. **Bicep `secretRef` — the deployed app reads secrets from Key Vault by identity.**
   `module-app.bicep` gained `keyVaultUri` + `keyVaultSecrets` params: it builds ACA
   `configuration.secrets` entries with `keyVaultUrl` + `identity` (the app's user-assigned MI) and
   surfaces them to the container as env vars via `secretRef` — never a plaintext value in the
   template. `main.bicep` threads the vault URI (from a new `core.bicep` `keyVaultUri` output) to
   the `api` app and to the `aiops` service app, and wires the `system-pulse-read-token` secretRef
   for `aiops`. The non-secret `$WP_KEY_VAULT_URI` is also injected so the app-side provider can
   resolve required secrets by identity. This is what finally **exercises** the already-granted
   `Key Vault Secrets User` role (`4633458b-17de-408a-b874-0445c86b69e6`), which stays
   least-privilege: read-only (Secrets User, not Officer), scoped to the specific vault, and NOT
   granted to the public `web` SPA (which reads no runtime secret).

5. **Fail closed (guardrail #4).** When a vault IS configured but a **required** secret is
   missing/inaccessible/empty, composition **raises `SecretResolutionError` and refuses to start** —
   it never silently continues with an empty/`None` token. Concretely, `_add_system_pulse` eagerly
   probes the token when a vault is configured, outside the try/except that omits an optional
   connector, so the error propagates. The env-var fallback path applies **only** when Key Vault is
   intentionally not configured. No secret value or SDK error message is ever logged or placed in an
   exception — errors carry the secret **name** and failing error **class name** only.

## Consequences

- **+** Keyless in fact, not just in spirit: runtime secrets are read from Key Vault by Managed
  Identity; only the non-secret vault URI and secret *names* live in code/config.
- **+** The `Key Vault Secrets User` grant is now **used** (ACA `secretRef` + app-side provider),
  closing the provisioned-but-unused gap, while staying least-privilege (read-only, vault-scoped,
  web excluded).
- **+** Fail-closed by construction: a misconfigured/inaccessible vault refuses to start rather than
  degrading to an unauthenticated/empty token.
- **+** Existing local-dev and CI keep working: with no `$WP_KEY_VAULT_URI`, the env-var fallback is
  used exactly as before — no test or workflow changes required.
- **−** There are now two keyless layers for the same secret (the ACA `secretRef` and the app-side
  provider). This is deliberate defense-in-depth — the app-side provider is authoritative and
  fail-closed; the `secretRef`-injected env is a keyless fallback — but it is a small amount of
  redundancy to keep in mind when reasoning about the deployed config.
- **TODO(human):** create the real `system-pulse-read-token` secret in the platform Key Vault (out
  of band, never committed) and set `$WP_KEY_VAULT_URI` for the deployed apps; extend
  `keyVaultSecrets` as further runtime secrets are added (e.g. future connector tokens).
