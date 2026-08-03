# Security & Trust Model

Trust is the product. These rules are **non‑negotiable** and are enforced by
`.github/copilot-instructions.md`, the `security-review` skill, and the PR security workflow.

## Data boundary

- **In‑boundary by construction.** All runtime components deploy into the **customer's** Azure
  subscription. PHI/PII, log bodies, and workload configuration are processed and stored **only**
  in the customer boundary.
- **Only signed content flows in.** Packs (workload/rule/telemetry/dependency/ops) are the *only*
  inbound artifact. They carry knowledge, never data.
- **Nothing sensitive flows out.** Optional, explicitly opted‑in, **aggregated and PII‑free**
  findings may be exported. Default is no egress.
- **No PHI/PII in this repository** — no customer data, no sample patient/records data, no
  captured logs. No Epic/SAP proprietary IP or SDKs are vendored here.

## Identity & secrets

- **Keyless everywhere.** Managed Identity via `DefaultAzureCredential`. No connection strings,
  keys, or tokens in code, config, or packs.
- Secrets that must exist at runtime live in **Key Vault**, referenced by identity.
- CI uses **OIDC federation** to Azure — no long‑lived cloud credentials in GitHub secrets.

### Keyless release variables (OIDC)

The `release` workflow authenticates to Azure with **OIDC federation** and consumes only
**non‑secret repository/environment variables** — never cloud credentials:

| Variable | Purpose |
|----------|---------|
| `AZURE_CLIENT_ID` | Federated identity client id used for OIDC login (no secret) |
| `AZURE_TENANT_ID` | Entra tenant id |
| `AZURE_SUBSCRIPTION_ID` | Target subscription |
| `AZURE_RESOURCE_GROUP` | Target resource group |
| `AZURE_LOCATION` | Azure region |
| `ACR_NAME` | Container Registry name (without `.azurecr.io`) |

Deployment stays keyless end‑to‑end: images are pulled with **AcrPull**, queues are read/written
with **Storage Queue Data Contributor** (KEDA queue scalers authenticate with the same
user‑assigned identity — no connection strings), and runtime secrets are read with **Key Vault
Secrets User** — all via the shared user‑assigned Managed Identity. The Storage account has
**shared‑key access disabled**, and the Container Apps environment ships logs to **Azure Monitor**
(routed to Log Analytics via a diagnostic setting) so **no Log Analytics shared key is ever read**.
The Bicep emits **no keys or connection strings** as outputs. Do **not** place any of these values,
or Azure credentials, in GitHub secrets
or in the workflow.

### Release identity — required least‑privilege roles

The six variables above are **not sufficient on their own**: the federated OIDC principal
(`AZURE_CLIENT_ID`) must be **granted Azure RBAC ahead of the first release**, or a fresh deploy
will fail. Grant the **narrowest** roles that cover what each job does, scoped as tightly as
possible (prefer the target resource group; subscription scope only where a role can't be RG‑scoped):

| Capability the release needs | Role (least privilege) | Suggested scope |
|------------------------------|------------------------|-----------------|
| Create the resource group (`bootstrap`) — skip if the RG is pre‑created | **Contributor** (RG create is subscription‑level) | Subscription |
| Create the Azure Container Registry (`bootstrap`) | **Contributor** | Resource group |
| Push images to ACR data plane (`build-images`) | **AcrPush** | The ACR |
| Create/update the RBAC role assignments the Bicep declares (AcrPull, Storage Queue Data Contributor, Key Vault Secrets User) | **Role Based Access Control Administrator** (`Microsoft.Authorization/roleAssignments/write`) | Resource group |
| Create/update Container Apps, Jobs, and the managed environment (`deploy-infra`) | **Container Apps Contributor** (or resource‑group **Contributor**) | Resource group |

Notes:
- If the resource group is created out‑of‑band, drop the subscription‑scoped **Contributor** and
  grant everything at the **resource group** scope for tighter least privilege.
- **Role Based Access Control Administrator** is required because the Bicep creates role
  assignments; plain Contributor cannot write `roleAssignments`. Constrain it to the RG (and, where
  supported, condition it to only the specific role definitions above).
- These grants are for the **deployment identity** only. Runtime stays keyless via the user‑assigned
  Managed Identity and the AcrPull / Storage Queue Data Contributor / Key Vault Secrets User
  assignments the Bicep creates.

## Fail‑closed behavior

- Unknown or invalid **pack signature** → refuse to execute.
- Unknown resource type, missing evidence, or **low confidence** → surface for a human, do not
  act on it.
- **No automatic remediation** of customer infrastructure. AIOps proposes; humans dispose.
  Remediation guidance is advisory (with a "call support" path), never auto‑applied.

## Pack integrity

- Packs are hashed (**SHA‑256**) and signed (**HMAC**); the Packs Engine **verifies before
  execute**. Version pinning records which pack version ran against which workload (auditable).

## Multi‑tenant isolation (MSP model)

- Strict per‑client isolation (partition/row scoping + RBAC). A client can never read another
  client's data. Customer‑owned + **Azure Lighthouse** is preferred where possible.

## Reporting a vulnerability

Internal Microsoft process: file a private security issue and tag the Security/Release owner in
`.github/CODEOWNERS`. Do **not** open a public issue. The PR security workflow
(`.github/workflows/security.yml`) runs CodeQL, dependency review, secret scanning and the
`security-review` skill on every pull request.
