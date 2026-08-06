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

- Packs carry a **SHA‑256 content hash over their canonical bytes** (the same canonicalization
  `src/shared/signing.py` signs over — whole manifest + body, volatile integrity fields excluded);
  the Packs Engine **verifies this hash before execute** (fail‑closed), so tampering with any
  manifest field (`targets`/`type`/`id`/`version`) or the body is detected. This hash is
  **tamper‑evidence in transit, NOT authenticity**.
- **First‑party / shipped packs get hash‑only integrity today.** The canonical content hash is
  **required** at the load boundary — a bundled pack that omits it is **refused** — but first‑party
  **authenticity (signature) enforcement is DEFERRED** to the offline signing‑key / pinned
  trust‑root decision (issues #37/#44). Shipped packs are **not signed or signature‑verified
  today**. A first‑party pack that nonetheless carries a detached signature is still **not**
  silently trusted: a present signature must cryptographically verify, so a present‑but‑unverifiable
  signature is rejected **fail‑closed** (never accepted on the strength of its hash alone).
- **Imported / third‑party packs are held to the stricter authenticity bar now.** They must carry a
  **detached Ed25519 signature over their canonical bytes** (`src/shared/signing.py`) that verifies
  before the pack is admitted or run. The signature envelope is self‑describing — it names the
  algorithm, a base64 detached signature, a `key_id` hint (never a secret), and the SHA‑256
  `canonical_digest` it covers.
- **Keyless + offline signing (verification path).** Signing is done **offline** in Microsoft's own
  infrastructure; the customer platform holds **no private key** and only **verifies**, selecting a
  pinned Ed25519 **public** key from a trust bundle by the signature's `key_id`. An empty/unpinned
  trust root rejects the pack (fail‑closed). (A legacy symmetric HMAC check remains as an
  independent, optional gate and is not the direction of record.)
- Version pinning records which pack version ran against which workload (auditable).

## Multi‑tenant isolation (MSP model)

- Strict per‑client isolation (partition/row scoping + RBAC). A client can never read another
  client's data. Customer‑owned + **Azure Lighthouse** is preferred where possible.

## Reporting a vulnerability

Internal Microsoft process: file a private security issue and tag the Security/Release owner in
`.github/CODEOWNERS`. Do **not** open a public issue. The PR security workflow
(`.github/workflows/security.yml`) runs CodeQL, dependency review, secret scanning and the
`security-review` skill on every pull request.
