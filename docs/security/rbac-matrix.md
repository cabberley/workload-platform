# Least-privilege RBAC matrix

Every Azure interaction the platform performs, mapped to the **narrowest** role that works, the
tightest scope, and *why nothing narrower works*. This matrix is grounded in the actual clients
constructed at the composition root ([`src/cli/wiring.py`](../../src/cli/wiring.py)), the
identity→component wiring ([`infra/bicep/main.bicep`](../../infra/bicep/main.bicep)), and the roles
provisioned in [`core.bicep`](../../infra/bicep/modules/core.bicep) /
[`grafana.bicep`](../../infra/bicep/modules/grafana.bicep). Read it with the
[threat model](threat-model.md).

## Per-component managed identities (issue #79)

The platform runs under **four distinct user-assigned managed identities** — there is **no** shared
runtime identity ([`core.bicep`](../../infra/bicep/modules/core.bicep) declares `identityApi`,
`identityWorker`, `identityWeb`, `identityGrafana`; [`main.bicep`](../../infra/bicep/main.bicep)
threads each into its ACA app/Job):

| Identity | Runs | Posture |
|----------|------|---------|
| **`identityApi`** | the `api` core (single **active** writer) | **state-writer** |
| **`identityWorker`** | the six capability modules — services `aiops`, `alerts` and jobs `discovery`, `quality_checks`, `reassessments`, `dependency_graph` | **state-writer** (its role set is the **union** of what those six modules need — they are not individually identity-isolated) |
| **`identityWeb`** | the static `web` SPA | **read-only** — no write role, no Key Vault, no queue |
| **`identityGrafana`** | the Managed Grafana data-source principal | **read-only** — Azure Monitor read only |

**`api` and `worker` are the *only* state-writers.** Only these two identities are granted the
state-store write data roles (Storage Blob Data Contributor + Storage Table Data Contributor at the
storage-account scope — [`core.bicep`](../../infra/bicep/modules/core.bicep)). This is
**RBAC-enforced, not a convention**: the `web` and `grafana` identities are deliberately excluded,
and a post-deploy CD gate ([`scripts/cleanup_verify_state_writers.py`](../../scripts/cleanup_verify_state_writers.py),
run from [`release.yml`](../../.github/workflows/release.yml)) removes any non-`api`/`worker`
principal holding **one of three enumerated built-in state-write roles** at the storage account and
**fails the release fail-closed** if one remains. The gate's enforced `STATE_WRITE_ROLE_IDS` set is
**Storage Blob Data Owner** (`b7e6dc6d-f1e8-4753-8033-0f276bb0955b`), **Storage Blob Data
Contributor** (`ba92f5b4-…`) and **Storage Table Data Contributor** (`0a9a7e1f-…`); the Bicep grants
the two Contributor roles (not Owner) to `api`/`worker`, and the gate additionally treats Blob Data
**Owner** as a write role to catch any legacy/stray Owner grant. **Scope limit:** the gate matches on
these three **built-in role GUIDs** only — a principal granted equivalent write access via a **custom
RBAC role** (e.g. `dataActions` like `Microsoft.Storage/.../blobs/write|delete` or the Table
equivalent) has a different definition id and is **not** detected/cleaned; extending the gate to
inspect custom-role `dataActions` is tracked as **#98**. *(Shared-key exfiltration is out of scope —
`allowSharedKeyAccess=false`.)*

**Runtime is keyless — via three distinct mechanisms (do not conflate them).** (a) **In-process
SDK clients** authenticate with the component's **own** user-assigned Managed Identity via
`DefaultAzureCredential` (each container gets `AZURE_CLIENT_ID` set to its identity's client id —
[`module-app.bicep`](../../infra/bicep/modules/module-app.bicep),
[`module-job.bicep`](../../infra/bicep/modules/module-job.bicep)) — this is the credential
*mechanism* for ARG and Azure Monitor (whose SDKs are installed) and, **once wired**, for network
topology and the Azure state backend (whose SDKs live in the optional `.[azure]` extra, **not**
installed by the deployed images — see the bucket note and rows below); (b) **ACR image pull** and
**KEDA queue-depth scaling** use **ACA managed-identity bindings** (`identity: identityId` on the
registry and queue scale rule), **not** `DefaultAzureCredential`; (c) **deployment/CD** uses
**GitHub OIDC** (see the Deployment table). No keys, secrets, or connection strings in any of the
three. Non-secret configuration values (a webhook URL, a subscription id) are read from environment
variables; **runtime secrets and connector bearer tokens are resolved from Key Vault BY the Managed
Identity** at composition time (issue #85, [ADR 0012](../adr/0012-key-vault-secret-injection.md)):
[`shared/secret_provider.py`](../../src/shared/secret_provider.py) resolves them when `$WP_KEY_VAULT_URI` is
configured, falling back to an env var **only** for local development. The Bicep now declares Key
Vault-backed `secretRef`/`secrets` (resolved by the app identity) — e.g. `system-pulse-read-token`
for `aiops` — and threads the vault URI ([`module-app.bicep`](../../infra/bicep/modules/module-app.bicep),
[`main.bicep`](../../infra/bicep/main.bicep)). Resolution **fails closed**: a configured vault that
cannot supply a required secret refuses to start. The **Key Vault Secrets User** role assignment (on
`api`/`worker`) is therefore now **used** — see that row (**#85**).

**External surfaces.** Two surfaces are reachable from outside the boundary today: the static
**Web** SPA (anonymous, read-only) and the **public Azure Managed Grafana** instance (#58 —
`publicNetworkAccess: 'Enabled'`, [`grafana.bicep`](../../infra/bicep/modules/grafana.bicep)).
Grafana is **Entra-SSO authenticated** with admin API keys disabled (`apiKey: 'Disabled'`). **What
the deploy wires is only the instance, its public endpoint, and the `identityGrafana` read-role
assignments (Monitoring Reader + LA Reader).** The telemetry data-flow is **not** wired: the Azure
Monitor data source (`azureMonitorWorkspaceIntegrations: []`), dashboard import, the **Grafana
Editor** provisioning principal, and the console deep-link (`VITE_GRAFANA_URL`) are documented
**manual steps** that CD does not run — see the Grafana rows below and the Deployment table.

> **Reading the Status column as two buckets.** Present-tense capability = **✅ wired today**
> (AcrPull, KEDA queue-depth polling, the per-component identity assignments, the
> *provisioned-but-unused* KV Secrets User assignment, and the read-plane role **assignments**:
> Reader (RG), Storage Blob/Table Data Contributor (storage), Monitoring Reader (RG), Log Analytics
> Reader (workspace)). **A ✅ on a role means the *assignment* is deployed — not that the consumer
> *flow* is wired.** Several consumers of those roles are still **⚠️ (flow intended / not wired)**:
> the whole **Azure state backend** (Blob/Table) persists to the **LOCAL** backend today (its SDKs
> live in the optional `.[azure]` extra, not installed by the deployed images, and the Bicep sets no
> `WORKLOADS_STATE_BACKEND=azure` — **R6**, #81), the in-app Azure Monitor connector needs
> workspace/resource env, and **subscription-wide ARG / network-topology discovery needs a
> *subscription*-scope Reader that is *not* granted** (only RG-scoped Reader was — part of the
> topology-not-wired story). **🔒** = pending a gated decision.

**Legend — provisioning status**

- ✅ **Provisioned** — the role **assignment** exists in Bicep
  ([`core.bicep`](../../infra/bicep/modules/core.bicep) or
  [`grafana.bicep`](../../infra/bicep/modules/grafana.bicep)). A ✅ means the *grant* is deployed; the
  consuming *flow* may still be intended (noted per row).
- ⚠️ **Flow intended / not wired** — the role assignment may be deployed, but the consumer is not
  wired end-to-end (missing SDK, env/config, backend selection, or scope); the client fails closed
  until wired.
- 🔒 **Pending decision** — aspirational; blocked on a gated open decision (do not wire yet).
- N/A — not an Azure RBAC role (app-plane token, filesystem, or in-process).

## Runtime interactions — one row per component

Each row is a runtime component, the identity it runs as, and the role(s) that identity is granted.
GUIDs are the built-in role definition ids ([`core.bicep`](../../infra/bicep/modules/core.bicep)
lines 51-66, verified against the tenant). **The six capability modules all run under
`identityWorker`**, so each holds that identity's full (union) role set — the per-module "Azure
interaction / minimal role" column below is the interaction *that module* drives; the aggregate is
in the **`worker` identity** row.

| Component | Runs as | Azure interaction | Minimal role (GUID) | Scope | Justification (why nothing narrower) | Guardrail | Status |
|-----------|---------|-------------------|---------------------|-------|--------------------------------------|-----------|--------|
| **discovery** (job) | `identityWorker` | Read the estate via **Azure Resource Graph** (`Resources \| project id,name,type,tags` — [`arg.py`](../../src/modules/discovery/arg.py)) | **Reader** (`acdd72a7-…`) | **Resource group** (granted); subscription for full-estate (not granted) | ARG is a read-only projection; Reader is the narrowest built-in that can enumerate resources across a scope — no data-plane or write right. **RG-scoped Reader is deployed (#80)**; subscription-wide discovery needs a broader **subscription-scope** Reader that an RG-scoped deployment cannot create. | Least privilege · keyless · no-PII-egress | ✅ *(Reader RG-scoped #80; ARG job active; subscription scope not granted)* |
| **quality_checks** (job) | `identityWorker` | Pure evaluation over the read-only estate; **persists** its assessment **via the API** (worker POSTs the result; the API commits it) | *(no direct Azure read; no direct worker write — API-mediated)* | storage account *(written by the API)* | Runs rule packs over an in-memory estate view; it has **no cloud read role of its own** and does **not write state directly** — the worker ([`worker.py`](../../src/cli/worker.py)) is compute-only and POSTs the result to the API single writer, which commits it. The worker's Blob/Table grant is **unexercised** (#97). | Least privilege · fail-closed | ✅ *(persistence API-mediated; deployed jobs currently submit nothing — no workload scope; worker write grant unexercised #97)* |
| **reassessments** (job) | `identityWorker` | Re-run assessments on a schedule; **persists** results **via the API** (worker POSTs; the API commits) | *(no direct worker write — API-mediated)* | storage account *(written by the API)* | Same as quality_checks — evaluation only, **no dedicated cloud read and no direct state write**; results are POSTed to the API single writer, which commits them. Worker write grant unexercised (#97). | Least privilege | ✅ *(persistence API-mediated; deployed jobs currently submit nothing — no workload scope; worker write grant unexercised #97)* |
| **dependency_graph** (job) | `identityWorker` | *Intended:* read **network topology** via `azure-mgmt-network` ([`topology.py`](../../src/modules/dependency_graph/topology.py)) | **Reader** (`acdd72a7-…`) | **Subscription** (`$WP_SUBSCRIPTION_ID`) | Topology enumeration is read-only ARM; Reader is the narrowest that can list network resources. **Flow not wired** — `azure-mgmt-network` is absent from `pyproject.toml`, `$WP_SUBSCRIPTION_ID` is unsupplied, and only **RG-scoped** Reader was granted (#80); a **subscription-scope** Reader is **not** granted, so subscription-wide topology has no scope. | Least privilege · keyless | ⚠️ *(flow not wired: SDK absent, env unset, subscription-scope Reader ungranted)* |
| **aiops** (service) | `identityWorker` | Query **Log Analytics** (`LogsQueryClient`) + **Azure Monitor metrics** (`MetricsClient`) ([`azure_monitor.py`](../../src/modules/aiops/connectors/azure_monitor.py)); read **System Pulse** telemetry | **Log Analytics Reader** (`73c42c96-…`) + **Monitoring Reader** (`43d0d8ad-…`); System Pulse = app-plane read token (N/A) | LA Reader = the specific workspace; Monitoring Reader = RG | Reads bounded, aggregated KQL/metrics only; workspace-scoped LA Reader + RG-scoped Monitoring Reader are the narrowest built-ins that can run those queries — no ingestion/write. **Roles assigned to the worker identity (#80)**; the in-app connector flow still needs `$AZURE_MONITOR_WORKSPACE_ID`/`$AZURE_MONITOR_RESOURCE_IDS` env. System Pulse token is resolved from Key Vault by the worker identity when `$WP_KEY_VAULT_URI` is set (secret `system-pulse-read-token`, fail-closed), else the local-dev env fallback (**#85**, [ADR 0012](../adr/0012-key-vault-secret-injection.md)). Metrics endpoint is SSRF-validated before a token is minted. | Least privilege · keyless · fail-closed · no-PII-egress | ✅ *(LA/Monitoring Reader assigned #80; in-app connector env unwired)* |
| **alerts** (service) | `identityWorker` | Route findings to notification channels; **the single findings-OUT boundary crossing** ([`module.py`](../../src/modules/alerts/module.py), [`channels.py`](../../src/modules/alerts/channels.py)) | *(no Azure ARM role; outbound webhook — N/A ARM)* | the configured notification endpoint only | Not an Azure ARM/data-plane call. **Egress is opt-in and not deployed by default** — the notifier is constructed only when `$WP_ALERT_WEBHOOK_URL` is supplied ([`wiring.py`](../../src/cli/wiring.py) `_add_notifier`) and the Bicep supplies none ([`main.bicep`](../../infra/bicep/main.bicep)). **When configured, the egress controls ARE enforced:** HTTPS-only (fail-closed `require_https_webhook`) with host-shape/port validation (**not** an SSRF range-block — `https://` to loopback/private/link-local/metadata IPs is accepted; range-blocking is residual **#95**), the channel is **blind** (no response body returned), and a strict **key** allowlist payload (`findingId`, `severity`, `channel`, `runbook`) with the out-of-boundary `findingId` **opaqued** (#78). **The `channel`/`runbook` *values* are operator-authored Ops-pack strings copied verbatim and are *not* value-scrubbed — keeping them PII-free is the pack author's responsibility; value redaction = #91.** Malformed/transport errors use constant messages that never reveal host/path/query; the insecure-scheme config error reports scheme+host in-boundary. See the threat model's [findings-OUT boundary](threat-model.md#trust-boundaries). | No-PII-egress · fail-closed · keyless | ✅ *(structure/keys enforced #78/#84; channel/runbook values unscrubbed #91; range-block #95; webhook delivery opt-in — not deployed by default)* |
| **api** (service) | `identityApi` | *(intended)* The **single writer**: dispatch work to queues, read runtime secrets, **write state** (Blob/Table) — *state persistence defaults to the **LOCAL** SQLite backend (§api status) and **no client enqueues** to the queues (only KEDA polls depth); **Key Vault secret injection is now wired** (#85): `$WP_KEY_VAULT_URI` is threaded so the app-side provider resolves runtime secrets by identity (no api-specific required secret wired yet)* | **AcrPull** (`7f951dda-…`) · **Storage Queue Data Contributor** (`974c5e8b-…`) · **Key Vault Secrets User** (`4633458b-…`) · **Storage Blob Data Contributor** (`ba92f5b4-…`) · **Storage Table Data Contributor** (`0a9a7e1f-…`) | AcrPull = the ACR; Queue/Blob/Table = the platform storage account; KV Secrets User = the platform Key Vault | The API is the (intended) sole state-writer, so it is granted the Blob + Table Data Contributor data roles (Contributor ⊇ Reader; the store creates and updates blobs/entities). Queue Data Contributor covers KEDA depth reads **and** the *intended* enqueue (no producer client enqueues today). KV Secrets User (get/list only) backs the keyless secret provider (**#85**, now used — the `aiops` worker consumes `system-pulse-read-token`; the api provider is enabled for future config). AcrPull to pull its image. Nothing narrower writes state. | Least privilege · keyless · provenance | ✅ *(role assignments deployed #80; KV injection wired #85; Azure state backend defaults local — R6/#81; no enqueue client)* |
| **worker** (identity — the six modules above) | `identityWorker` | **Aggregate (union) role set** for all six capability modules | **AcrPull** (`7f951dda-…`) · **Storage Queue Data Contributor** (`974c5e8b-…`) · **Key Vault Secrets User** (`4633458b-…`) · **Reader** (`acdd72a7-…`) · **Monitoring Reader** (`43d0d8ad-…`) · **Log Analytics Reader** (`73c42c96-…`) · **Storage Blob Data Contributor** (`ba92f5b4-…`) · **Storage Table Data Contributor** (`0a9a7e1f-…`) | AcrPull/Queue/Blob/Table/KV = storage/ACR/KV as for api; Reader + Monitoring Reader = RG; LA Reader = the workspace | A **state-writer** (holds the Blob/Table Data Contributor set, like api) because the modules persist assessments; plus the read-plane roles their connectors need (ARG Reader, aiops Monitoring/LA Reader). **Honest caveat:** the six modules share this one identity, so component-level separation *within* the worker is not achieved — e.g. `discovery` (read-only ARG) physically holds the write set. The api-vs-worker split *is* RBAC-enforced (only `api`+`worker` may hold a write role). **Residual (#97):** the worker's Blob/Table Data Contributor grant is **deployed-but-unexercised** — the worker ([`worker.py`](../../src/cli/worker.py)) is compute-only and submits results via HTTP through a **read-only `ApiStateReader`**, so the API is the only *active* code writer; the standing write grant means a compromised worker could write state directly, bypassing API validation (tighten to API-only writer at RBAC — **#97**). Finer per-module split is also a candidate follow-up. | Least privilege *(per-identity, not per-module)* · keyless | ✅ *(all assignments deployed #79/#80; worker write grant unexercised — #97; several consumer flows ⚠️)* |
| **web** (service) | `identityWeb` | Pull its container image; serve the static SPA (talks only to the API) | **AcrPull** (`7f951dda-…`) — **and nothing else** | the ACR only | The web front-end is a static nginx SPA that reads **no** runtime secret and touches **no** queue or state. It is deliberately granted **AcrPull only** — no Key Vault, no queue, no state-write role ([`core.bicep`](../../infra/bicep/modules/core.bicep) creates only `acrPullWeb`; the KV/write assignments explicitly exclude web) — so the public, internet-facing front-end has the smallest possible blast radius. | Least privilege · keyless | ✅ |
| **grafana** (Managed Grafana) | `identityGrafana` | *(at query time, once a data source is configured)* Read **Azure Monitor metrics** + **Log Analytics logs** for dashboards | **Monitoring Reader** (`43d0d8ad-…`) + **Log Analytics Reader** (`73c42c96-…`) | Monitoring Reader = RG; LA Reader = the workspace | Read-only Monitoring/LA Reader are the narrowest roles that let a Grafana data source query metrics/logs; held by a **dedicated read-only** identity (no AcrPull — Grafana is a managed service; no write/admin). **The role *assignments* are deployed (#58 — [`grafana.bicep`](../../infra/bicep/modules/grafana.bicep));** the data source that would consume them is **not** configured (`azureMonitorWorkspaceIntegrations: []`) — see the next row. | Keyless · least privilege · no-PII-egress | ✅ *(read-role assignments deployed #58)* |
| **grafana — data source + dashboards + Editor + deep-link** | *(separate Entra principal)* | Configure the Azure Monitor **data source**, import **dashboards**, wire the console **deep-link** ([`infra/grafana/README.md`](../../infra/grafana/README.md)) | **Grafana Editor** (Grafana data-plane role, not Azure ARM) | the Managed Grafana instance | **Not wired by the deploy — bucket B.** The Bicep sets `azureMonitorWorkspaceIntegrations: []` (no data source); configuring the data source, importing dashboards, and assigning **Grafana Editor** to a **separate** Entra principal (CI MI / operator — never the read-only `identityGrafana`) are documented **manual `az grafana …` steps** that CD does not run ([`release.yml`](../../.github/workflows/release.yml)). Editor (not Admin) is least privilege; admin API keys are disabled. The console deep-link is also unwired — the web image supplies no `VITE_GRAFANA_URL` ([`Dockerfile.web`](../../infra/docker/Dockerfile.web)), consumed by [`GrafanaPanel.tsx`](../../src/web/src/panels/GrafanaPanel.tsx). | Least privilege *(separation of duties)* · keyless | ⚠️ *(flow not wired: data source `[]`, Editor unassigned, deep-link absent; #86 dashboards not yet emitting — untracked candidate follow-up)* |
| **audit event store** (write path) | `identityApi` *(the active audit writer)* | **Append** tamper-evident audit records to the **active state backend** — the **LOCAL** SQLite store by default; **Azure Table storage when the `azure` backend is selected** ([`audit.py`](../../src/shared/audit.py), `StateStore.append_audit`) | **Storage Table Data Contributor** (`0a9a7e1f-…`) *(the state-write set; the API is the active writer — the worker's grant is unexercised, #97)* | the platform storage account | The append-only audit trail (#59) is written by **`identityApi`** — the API constructs the writable store **and** the audit emitter; the worker never writes audit directly (#97). It is **write-append for provenance** (guardrail #8): each record chains `sha256(canonical ‖ prevHash)` so field-tampering/reorder/insert/delete/tail-truncation are **detectable on read *relative to a trusted anchored HEAD*** (`verify_audit_chain`). **Limitation:** the event rows and the chain HEAD are **co-located in one mutable Table partition**, so a Table-Contributor holder can coordinate-rewrite history+HEAD undetectably — an out-of-band/WORM HEAD anchor is a follow-up (**#81**). **The Azure Table persistence path is intended — the backend defaults local (R6/#81).** **Coverage complete + fail-closed, audit-before-write (#99, [ADR 0014](../adr/0014-fail-closed-audit-emission.md)):** `run.executed`, finding-emitted, **and** the state-mutating `put_estate`/`put_graph`/`snapshot` endpoints all emit a bounded-subject audit event (only the three state-mutation subjects embed an opaque `wl:<digest>` full-SHA-256 token — **PII-free by construction**, never the raw workload name; `finding.emitted` still carries a raw `<workload>#count=N` and `run.executed` carries the module identifier), and emission is **fail-closed and ordered audit-BEFORE-write** for these security-material actions — the durable append runs first and the mutation only if it succeeds, so a durable-append failure raises `AuditPersistenceError`, the mutating write **fails 5xx with no committed-but-unaudited state**, surfaced on `audit_emit_failures_total` (a narrow fail-open allowance remains for the non-material `pack.verify` breadcrumb; workload-ID grammar hardening for the pre-existing `finding.emitted` subject is tenant-isolation **#65**). | Provenance · append-only · least privilege | ✅ *(active writer identityApi; hash-chain vs trusted HEAD #59; co-located mutable HEAD + WORM #81; coverage complete/fail-closed #99; backend defaults local — R6/#81; worker grant unexercised #97)* |
| **all modules — work queues** | `identityApi` / `identityWorker` | KEDA reads queue length (queue-depth polling); *(intended)* api enqueues | **Storage Queue Data Contributor** (`974c5e8b-…`) *(broader than needed today)* | the platform storage account | **The only queue interaction today is KEDA depth polling** — the service loop is a heartbeat and does **not** enqueue/dequeue ([`serve.py`](../../src/cli/serve.py)); real producer/consumer wiring is a candidate follow-up. Depth polling needs only **Storage Queue Data Reader** — narrow it once the platform actually enqueues/dequeues. `web`/`grafana` are (correctly) not granted this. | Keyless · least privilege | ✅ *(granted as Contributor — broader than needed today; untracked follow-up)* |
| **Packs Engine — pack-signing trust root** ([`signing.py`](../../src/shared/signing.py), [`wiring.py`](../../src/cli/wiring.py)) | *(no runtime signing identity — verification-only)* | **Verify** imported-pack detached signatures against pinned Ed25519 **PUBLIC** keys | **None at runtime** — no Key Vault key op, no KV role | *(no Key Vault key; the trust bundle holds only public keys)* | **Resolved by #89 ([ADR 0010](../adr/0010-pack-signing-trust-root.md)): offline Microsoft Ed25519 signing + customer-side, verification-only, KEYLESS verification.** Microsoft signs packs **offline** in its own infrastructure (out of the customer boundary); the platform only **verifies** with a bundled trust root of pinned Ed25519 **public** keys (`config/trust-bundle.json` → [`TrustBundleVerifier`](../../src/shared/signing.py)), wired fail-closed into [`PacksEngine.verify_pack_for_import`](../../src/packs_engine/engine.py). This needs **no runtime Key Vault key op and no KV role** — verification is keyless. The former KV signer/verifier **stubs are removed** (Ed25519 is not a KV Keys algorithm, and the customer side never signs). **ECDSA-P256-in-KV-HSM signing was considered and NOT chosen** (would put a signing key op + **Key Vault Crypto User** role inside the customer runtime; rejected — see ADR 0010). Digest-addressed content store + digest resolution is **#44** (which did **not** wire any signing key); pack import/assign admission (which calls `verify_pack_for_import`) is **#37**. | Detached pack signing · **keyless (verify-only)** · least privilege | ✅ *(#89 trust root wired fail-closed; import admission gate #37; real MS public keys to be pinned)* |

> **Signing-key note (resolved by #89).** Issue #61 had framed a pending signing key as *Key Vault
> Secrets User*, later *Key Vault Crypto User*. **#89 resolved the trust root as customer-side,
> verification-only, and keyless** ([ADR 0010](../adr/0010-pack-signing-trust-root.md)): Microsoft
> signs packs **offline** with an Ed25519 private key held outside the customer deployment, and the
> platform only **verifies** with distributed Ed25519 **public** keys pinned in
> `config/trust-bundle.json`. There is therefore **no runtime Key Vault key operation and no KV role
> for pack signing** — the KV `CryptographyClient` stubs are removed. The **ECDSA-P-256-in-KV-HSM**
> alternative (which *would* have needed **Key Vault Crypto User**) was **explicitly not chosen**
> because it would place a signing capability + KV role inside the customer runtime.

## Application-layer API/console authorization — Entra app-role RBAC (issue #64)

The per-component identities above are **Azure control/data-plane** least privilege (which identity
may read ARG, write Blob/Table, …). Orthogonal to that is **who may call the API and what they may
do** — an *application-layer* concern for console/human and service-to-service callers, owned by
issue #64 ([ADR 0016](../adr/0016-entra-auth-console-api-rbac.md)). It is **keyless** (Entra OIDC
bearer tokens validated against tenant **JWKS public keys** — no secret anywhere;
[`src/shared/auth/`](../../src/shared/auth/)) and **deny-by-default**.

| App role (Entra app role) | Granted actions | Enforced on |
|---------------------------|-----------------|-------------|
| **`Workloads.Reader`** | read the read-models | `GET` data endpoints (metrics, modules, packs, workloads, estate, graph, impact, findings, drift) when auth is enabled |
| **`Workloads.Operator`** | run modules; submit results/estate/graph/findings/snapshot | **all six state-mutating `POST` endpoints** — `/api/modules/{name}/run`, `/api/workloads/{workload}/results\|estate\|graph\|findings\|snapshot` |
| **`Workloads.Admin`** | Operator ⊇ Reader, plus future admin actions | (superset — no admin-only endpoint exists yet) |

- **Deny-by-default & fail-closed *by default*.** Auth is governed by an explicit
  `WP_AUTH_MODE ∈ {required, disabled}` that **defaults to `required`**. A `require_role(...)`
  FastAPI dependency ([`src/api/app/main.py`](../../src/api/app/main.py)) validates the bearer token
  then authorizes the required role. With auth enabled: missing/invalid token → **401**; valid token
  but insufficient role → **403**; it **never** falls open to the `system` actor for a mutating
  request. A **startup guard** refuses to serve when `required` and the tenant/audience are
  missing **or partial** (an `AuthConfigError` aborts start-up) — a forgotten deployment var is a
  loud failure, not a silent wide-open API. Running without auth requires the deliberate
  `WP_AUTH_MODE=disabled` opt-out (local/CI/tests; logs a warning). **`/api/health*` and `/` stay
  unauthenticated** (probes).

  | `WP_AUTH_MODE` | tenant + audience | Result |
  | --- | --- | --- |
  | `required` (default) | both present | **Enforced** |
  | `required` (default) | both absent | **Startup refuses to serve** |
  | `required` (default) | partial (one present) | **Startup refuses to serve** |
  | `disabled` | any | **No auth** (deliberate opt-out; warns) |
- **Keyless validation edge.** RS256 verified with `cryptography` (public key from JWKS `n`/`e`);
  `alg:none`/HMAC rejected; JWKS cached with bounded TTL, refreshed on unknown `kid`; HTTP + clock
  injectable so tests are network-free. Errors are **PII-free reason codes only** — never token or
  claims.
- **Audit actor from the validated claim.** Mutating endpoints derive the audit actor from the
  validated `oid` claim, **not** the `PRINCIPAL_ID_HEADER` — closing the spoofable-actor gap
  ([`resolve_actor`](../../src/shared/audit.py) now prefers a validated `principal_id`; the header is
  the no-auth local/worker fallback only).
- **Service-to-service (worker → API) — keyless, wired in code.** The worker
  ([`src/cli/worker.py`](../../src/cli/worker.py)) presents **its own managed identity** (#79):
  [`build_api_token_provider`](../../src/shared/auth/token_source.py) obeys the same `WP_AUTH_MODE`
  and, under `required`, mints an `<WP_AUTH_AUDIENCE>/.default` token via `DefaultAzureCredential`
  (kept at an injectable edge — keyless tests) and attaches `Authorization: Bearer`; under `disabled`
  it sends none; inability to mint **fails closed**. **No shared key.** The `Workloads.Operator` app
  role must be **assigned to `identityWorker`** at deploy time — an Entra app-role assignment
  (Microsoft Graph `appRoleAssignedTo`) that is **not ARM/Bicep-expressible**, so it is an `az rest`
  / Graph deploy step (see below).
- **Wiring status — honest.** Enforcement, the role model, the **fail-closed `WP_AUTH_MODE` default +
  startup guard**, the audit-actor change, the console token-attachment/MSAL sign-in, and the
  **worker's keyless bearer** are **wired in code and tested** (full fail-closed + header-spoof +
  mode-precedence + worker-bearer matrix, injected key/claims/credential seams — no real Entra). The
  non-secret `WP_AUTH_MODE`/`WP_AUTH_TENANT_ID`/`WP_AUTH_AUDIENCE` env is **threaded through Bicep**
  (`module-app.bicep`, `module-job.bicep`, `main.bicep`; `authMode` defaults to `required`). **Not
  yet done (deploy-time `TODO(human)`):** create the API + SPA **app registrations**, define the app
  roles, **assign `Workloads.Operator` to `identityWorker`** and the human/console principals (Graph
  `appRoleAssignedTo` via `az rest` — not ARM), set the deployment values for the API
  `WP_AUTH_TENANT_ID`/`WP_AUTH_AUDIENCE` params and SPA `VITE_AUTH_*` env, and add the SPA redirect
  URI. **Under the default `required` mode the API refuses to start until tenant+audience are
  provided** — fail-closed, never silently wide-open. ⚠️ *(code+tests green + Bicep env threaded;
  app-registration/role-assignment provisioning pending — #64)*

## Deployment / CI/CD (OIDC) identity — for completeness

The **release/CD** principal is separate from the runtime managed identities and authenticates to
Azure with **GitHub OIDC federation** (no cloud secrets in GitHub —
[`release.yml`](../../.github/workflows/release.yml)). It publishes container images and provisions
the infrastructure and the runtime role assignments; the **runtime** identities stay
least-privilege. This is a distinct **CI/CD plane**.

**Publishing images — AcrPush.** The release workflow does `az acr login` + `docker push` of the
`api`/`worker`/`web` images ([`release.yml`](../../.github/workflows/release.yml) build-images job),
which requires **AcrPush** on the registry (distinct from the runtime identities' AcrPull).

**Provisioning — the deploy principal needs *two* roles; neither alone suffices.**
[`core.bicep`](../../infra/bicep/modules/core.bicep) both **creates resources** (four user-assigned
managed identities, Log Analytics workspace, Storage account + queues, Key Vault, an ACA managed
environment, diagnostic settings) **and creates role assignments**; the deploy also provisions the
**public Azure Managed Grafana** instance and its read-role assignments
([`grafana.bicep`](../../infra/bicep/modules/grafana.bicep)). Azure **`Contributor` cannot authorize
role assignments** (it lacks `Microsoft.Authorization/roleAssignments/write`), so the CD/OIDC deploy
principal needs **RG-scoped `Contributor` *plus* RG-scoped `Role Based Access Control
Administrator`** (or `Owner`) — `Contributor` to create the resources and RBAC Administrator to
create the role assignments. This is the **CD/OIDC deploy principal**, distinct from the runtime
identities. It **also** runs the post-deploy api/worker-only-writer gate
([`scripts/cleanup_verify_state_writers.py`](../../scripts/cleanup_verify_state_writers.py)), whose
destructive cleanup intentionally stays on the CD identity, not a script identity.

| Capability | Role | Scope |
|------------|------|-------|
| **Publish container images** (`docker push` — [`release.yml`](../../.github/workflows/release.yml)) | **AcrPush** | the ACR |
| Create the resource group (skip if pre-created) | **Contributor** | Subscription |
| **Minimal sufficient pair for everything below** | **Contributor** + **Role Based Access Control Administrator** (or **Owner**) | Resource group |
| Create the four user-assigned **managed identities** ([`core.bicep`](../../infra/bicep/modules/core.bicep)) | **Managed Identity Contributor** | Resource group |
| Create **Log Analytics** workspace + **diagnostic settings** | **Log Analytics Contributor** + **Monitoring Contributor** | Resource group |
| Create **Storage** account + queues | **Storage Account Contributor** | Resource group |
| Create **Key Vault** | **Key Vault Contributor** | Resource group |
| Create **ACR** + push images | **Contributor** / **AcrPush** | Resource group / the ACR |
| Create the **ACA environment**, Apps & Jobs | **Container Apps Contributor** | Resource group |
| Create the **public Managed Grafana** instance ([`grafana.bicep`](../../infra/bicep/modules/grafana.bicep)) | **Contributor** (`Microsoft.Dashboard/grafana` write) | Resource group |
| Create the runtime + Grafana **role assignments** the Bicep declares | **Role Based Access Control Administrator** *(required — Contributor cannot do this)* | Resource group |

> **Grafana data-plane provisioning is separate — and not run by CD.** Configuring the Azure Monitor
> data source and importing dashboards use the **Grafana Editor** data-plane role held by a
> **separate** CI managed identity / operator principal (not the CD deploy principal, not the
> read-only `identityGrafana` data-source identity). These are documented **manual `az grafana …`
> steps** ([`infra/grafana/README.md`](../../infra/grafana/README.md)) that the release workflow does
> **not** perform — see the Grafana rows in the runtime table (bucket B).

## Summary (component → identity → role)

- **discovery** → `identityWorker` → **Reader** (RG) — ✅ *deployed #80; ARG job active; subscription scope not granted*
- **quality_checks** → `identityWorker` → *(state-write via worker; no own cloud read)* — ✅
- **reassessments** → `identityWorker` → *(state-write via worker; no own cloud read)* — ✅
- **dependency_graph** → `identityWorker` → **Reader** (subscription) — ⚠️ *flow not wired: SDK absent, env unset, subscription-scope Reader ungranted*
- **aiops** → `identityWorker` → **Log Analytics Reader** (workspace) + **Monitoring Reader** (RG); System Pulse read token (N/A ARM) — ✅ *roles #80; in-app connector env unwired*
- **alerts** → `identityWorker` → outbound webhook (N/A ARM) — ✅ *egress controls #78/#84 implemented; delivery opt-in, not deployed by default*
- **api** → `identityApi` → **AcrPull · Queue Data Contributor · KV Secrets User · Blob Data Contributor · Table Data Contributor** — ✅ *(state-writer; KV injection wired #85; Azure state backend defaults local R6/#81)*
- **worker** → `identityWorker` → the api set **plus Reader · Monitoring Reader · Log Analytics Reader** — ✅ *(state-writer + read-plane; union of the six modules)*
- **web** → `identityWeb` → **AcrPull only** — ✅ *(no write, no KV, no queue)*
- **grafana** → `identityGrafana` → **Monitoring Reader** (RG) + **Log Analytics Reader** (workspace) — ✅ *assignments deployed #58; data source/dashboards/Editor/deep-link ⚠️ manual*
- **audit event store** → **`identityApi`** (active writer; worker grant unexercised #97) → **Storage Table Data Contributor** (append) — ✅ *hash-chain tamper-evident vs a trusted HEAD #59; co-located mutable HEAD + WORM #81; coverage complete/fail-closed emit #99 (ADR 0014); **local SQLite by default***
- **CI/CD release identity** → **AcrPush** + **RG Contributor** + **RBAC Administrator** via GitHub OIDC — ✅ *(CI/CD plane, distinct from runtime identities)*
- **Pack-signing trust root** → **no runtime KV role** *(verification-only, keyless — #89/[ADR 0010](../adr/0010-pack-signing-trust-root.md))* — ✅ *(offline MS signing; platform verifies with pinned Ed25519 public keys)*

**The only state-writers are `api` and `worker`** (Storage Blob + Table Data Contributor) — and the
**API is the only *active* writer** (the worker's grant is unexercised, #97). Every other runtime
identity is read-only: `web` = AcrPull only; `grafana` = Monitoring/LA Reader only. The boundary is
**RBAC-enforced** and re-verified fail-closed by the post-deploy CD gate
([`cleanup_verify_state_writers.py`](../../scripts/cleanup_verify_state_writers.py)), which matches
the **three built-in state-write role GUIDs** only — a **custom RBAC role** granting equivalent
Blob/Table write `dataActions` is **not** detected (residual **#98**).

**Roles deployed but the consuming flow is intended / not wired (⚠️ flow):** the Azure **state
backend** (Blob/Table roles deployed, but persistence — including job/assessment writes and the
**audit Table** append path — defaults to the **LOCAL** SQLite backend — R6/#81), the **API enqueue**
path (Queue Data Contributor deployed, but **no producer client enqueues** — only KEDA polls queue
depth for scaling), the in-app Azure **Monitor** connector (roles deployed, but no workspace/resource env),
**subscription-wide discovery / network topology** (only **RG-scoped Reader** granted — a
**subscription-scope Reader** is the remaining RBAC gap, plus SDK + env), and the **Grafana telemetry
data-flow** (data source `[]`, dashboards, Editor principal, `VITE_GRAFANA_URL` deep-link are manual
steps CD does not run; #86 dashboards not yet emitting).

**Resolved decision (#89):** the pack-signing trust root is **offline Microsoft Ed25519 signing +
customer-side, verification-only, keyless verification** ([ADR 0010](../adr/0010-pack-signing-trust-root.md)).
The platform holds only pinned Ed25519 **public** keys (`config/trust-bundle.json`) and verifies
imported packs fail-closed via [`PacksEngine.verify_pack_for_import`](../../src/packs_engine/engine.py);
it performs **no Key Vault key operation and needs no KV role** for signing. The **ECDSA-P-256-in-KV**
alternative (which would have required **Key Vault Crypto User**) was considered and **not chosen**
because it would place a signing key op + KV role inside the customer runtime.

**Cross-cutting notes (see the threat model's [residual risks](threat-model.md#residual-risks--known-gaps)):**
per-component identities (**#79**, merged) now enforce the api/worker-only-writer boundary by RBAC —
the old shared-identity gap is **resolved**; the six worker-hosted modules still share one identity,
so finer per-module separation is a candidate follow-up. The **worker's** Blob/Table write grant is
**deployed-but-unexercised** — the worker is compute-only and writes state only *via* the API through
a read-only `ApiStateReader`, so the API is the sole *active* writer; tightening to an API-only writer
at the RBAC layer is tracked as **#97**. The queue grant is broader than current
functionality needs (**untracked — candidate follow-up**). The webhook egress **controls** are
implemented (#78 opaque ids; #84 HTTPS-only + host-shape/port validation + **key** allowlist; the channel is
blind — no response body returned), but over HTTPS the validator does **not** range-block
loopback/private/link-local/metadata destinations (residual **#95**) and **delivery is opt-in and not
deployed by default**; the egressed `channel`/`runbook` **values** are operator-authored and **not
value-scrubbed**, so their redaction (plus any future extra/tag fields) is tracked as **#91**. Key Vault secret injection is now implemented — runtime secrets/connector tokens resolve from Key Vault by managed identity (fail-closed), with the env-var path retained only as a documented local-dev fallback (**#85**, [ADR 0012](../adr/0012-key-vault-secret-injection.md)). Audit
records are hash-chain tamper-evident **relative to a trusted anchored HEAD** (**#59**), and persist
to **local SQLite by default** (Azure Table only when the `azure` backend is selected); because the
event rows and the chain HEAD are **co-located in one mutable Table partition**, a coordinated
history+HEAD rewrite by a state-write (Table Contributor) holder is not prevented — storage-layer
immutability (WORM) plus an out-of-band HEAD anchor is a follow-up (**#81**).
