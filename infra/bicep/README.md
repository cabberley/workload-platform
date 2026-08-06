# infra/bicep — in-boundary platform IaC

Bicep that provisions the shared, keyless, in-boundary platform (`main.bicep` → `modules/core.bicep`
plus the per-module ACA apps/jobs and Managed Grafana). Every component authenticates with its
**own per-component user-assigned Managed Identity** created in `core.bicep` (issue #79); there are
no keys, connection strings, or admin credentials anywhere in the templates or their outputs.

## Per-component identities & the API-only-writer boundary (issues #79/#97)

A single shared identity used to be assigned to every ACA app/job, so granting the state-store
write data roles to it let **every** component write state — the "the API is the only writer"
boundary was not actually enforced by RBAC. It is now: each component runs as its **own**
user-assigned identity, and the **state-store WRITE** data roles are granted to the **api identity
only** (issue #97 — the worker is compute-only and holds no Blob/Table write role).

| Identity | Runs as | State-store write? | Roles held |
|----------|---------|--------------------|------------|
| `wp-id-api-*` | `wp-api` (single-writer API core) | ✅ **writer** | AcrPull · Storage Queue Data Contributor · Key Vault Secrets User · **Storage Blob Data Contributor** · **Storage Table Data Contributor** |
| `wp-id-worker-*` | all module apps/jobs (`wp-aiops`, `wp-alerts`, `wp-discovery`, `wp-quality_checks`, `wp-reassessments`, `wp-dependency_graph`) | ❌ **compute-only** (reads + writes via the API) | AcrPull · Storage Queue Data Contributor · Key Vault Secrets User · Reader (RG) · Monitoring Reader (RG) · Log Analytics Reader (workspace) |
| `wp-id-web-*` | `wp-web` (read-only front-end) | ❌ **reader** | AcrPull |
| `wp-id-grafana-*` | Managed Grafana data source | ❌ **reader** | Monitoring Reader (RG) · Log Analytics Reader (workspace) |

**Only** `wp-id-api-*` holds `Storage Blob Data Contributor`
(`ba92f5b4-2d11-453d-a403-e96b0029c9fe`) and `Storage Table Data Contributor`
(`0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3`) at the storage-account scope (issue #97). The **worker** is
**compute-only** — it reads prior state via the API (a read-only `ApiStateReader`) and POSTs its
module result to the API, the single code path that commits state — so it is deliberately absent from
those assignments and **cannot write blobs or tables**. `wp-id-web-*` is likewise absent, so the
**web front-end cannot write blobs or tables** — it talks only to the API. The web identity also holds
**no Key Vault access**: the web component is a static nginx SPA with no
runtime `secrets`/Key Vault `secretRef` in `module-app.bicep`, so granting the public,
internet-facing frontend vault-wide secret read would needlessly widen its blast radius
(least-privilege, guardrail #7). Per the issue's "one for the worker/job" guidance, the module workers and jobs share a
single `worker` identity whose role set is the **union** of what those workers/jobs need (further
per-module splitting is possible future work).

Role-assignment names remain `guid(scope, identity, roleId)` so the templates stay idempotent; each
per-component identity yields a **distinct** assignment name for the same role + scope.

## Read-plane RBAC (least privilege, keyless)

The read-plane clients (ARG discovery, network topology, the aiops Azure Monitor connector) all run
inside the **worker/job** compute, so the read-plane roles are attached to the **`worker`** identity
(they moved off the old shared identity). Roles are assigned with stable `guid()` names so the
templates are idempotent. Every GUID is verified with
`az role definition list --name "<Role Name>" --query "[0].name" -o tsv`.

| Role | GUID | Scope | Declared in | Identity | Consumer(s) | Read vs write | Wired today? |
|------|------|-------|-------------|----------|-------------|---------------|--------------|
| AcrPull | `7f951dda-4ed3-4680-a7ca-43fe172d538d` | Container Registry | `core.bicep` | api · worker · web | image pulls | read | ✅ |
| Storage Queue Data Contributor | `974c5e8b-45b9-4653-ba55-5f855dd0fb88` | Storage account | `core.bicep` | api · worker | KEDA queue scalers + enqueue/dequeue | read+write | ✅ |
| Key Vault Secrets User | `4633458b-17de-408a-b874-0445c86b69e6` | Key Vault | `core.bicep` | api · worker | runtime secret reads by identity | read | ✅ |
| **Reader** | `acdd72a7-3385-48ef-bd42-f606fba81ae7` | **Resource group** | `core.bicep` | worker | ARG discovery (`modules/discovery/arg.py`); network topology (`modules/dependency_graph/topology.py`) | read | ARG ✅ · topology ⏳ |
| **Storage Table Data Contributor** | `0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3` | Storage account | `core.bicep` | **api** | Azure state backend tables (`shared/state.py` `AzureStateStore`) | read+write | ⏳ |
| **Storage Blob Data Contributor** | `ba92f5b4-2d11-453d-a403-e96b0029c9fe` | Storage account | `core.bicep` | **api** | Azure state backend snapshot/estate/graph/findings blobs (`shared/state.py`) | read+write | ⏳ |
| Monitoring Reader | `43d0d8ad-25c7-4714-9337-8ba259a9fe05` | Resource group | `core.bicep` (worker) · `grafana.bicep` (grafana) | worker · grafana | Azure Monitor connector metrics edge (`modules/aiops/connectors/azure_monitor.py`) **and** the Grafana data source | read | ✅ |
| Log Analytics Reader | `73c42c96-874c-492b-b04d-ab87d138a893` | **Log Analytics workspace** | `core.bicep` (worker) · `grafana.bicep` (grafana) | worker · grafana | Azure Monitor connector logs edge (`azure_monitor.py`, `LogsQueryClient.query_workspace`) **and** the Grafana data source | read | ✅ |

**Bold** rows are the read-plane roles added for issue #80, now attached to the identities that
genuinely need them (issue #79). `✅` = a client that runs in the deployed topology today; `⏳` =
provisioned but the consumer is not yet wired into deployment — granting the least-privilege role now
keeps the client **fail-closed** rather than fail-open when it is wired.

### Why write-tier storage data roles

`AzureStateStore` is the API core's single writer. It **creates** the `snapshots`/`workloads` tables
and the state container, writes the manifest entity that is its sole commit point
(`create_entity`/`update_entity`), and uploads the immutable version-scoped estate/graph/findings
blobs (`upload_blob`) as well as reading them back. Because it writes, it needs the **Contributor**
data roles (`Storage Table Data Contributor`, `Storage Blob Data Contributor`), not the read-only
`*Data Reader` variants. `Contributor ⊇ Reader`, so the same grant also covers any read-only
pack-content blob access under the api identity. The roles are scoped to the **storage
account** (the narrowest inline scope), granted to the **api identity only** (issue #97), and
account-level `allowSharedKeyAccess` is `false`, so this data-plane access is keyless (Managed
Identity only). The **worker** (compute-only) and the **web** reader identity never receive them.

### Monitoring Reader + Log Analytics Reader across two principals

The Azure Monitor connector (running in the **worker** compute) needs Monitoring Reader (metrics) and
Log Analytics Reader (KQL over the in-boundary workspace), and the **Grafana** data source needs the
same read pair. Because these are now **two distinct principals** (the `worker` identity and the
dedicated `grafana` identity, issue #79), each gets its **own** assignment: the worker's pair is
declared in `core.bicep`, the grafana pair in `grafana.bicep`. There is no `RoleAssignmentExists`
conflict — that error only occurs for the **same** principal + role + scope, and these are different
principals with distinct `guid()`-derived names. Both use **Monitoring Reader at resource-group
scope** (metrics span multiple platform resources — Container Apps, storage — not just the workspace)
and **Log Analytics Reader scoped to the single Log Analytics workspace** (the logs edge queries only
that one workspace, `LogsQueryClient.query_workspace`). The worker's `Reader` grant also transitively
covers the connector's in-RG reads (`*/read` includes `Microsoft.Insights/*/read` and
`Microsoft.OperationalInsights/workspaces/query/*/read`).

> **Migration note (already-deployed environments) — automated & enforced:** environments deployed
> before issue #79 used a **single shared identity** (`wp-id-<token>`) that held every role,
> including the state-store write roles. Incremental ARM deployment (`az deployment group create`)
> does **not** delete the identity or role assignments that were removed from the template, so a
> brownfield redeploy would leave that shared identity as a lingering **state-writer** — the
> API-only-writer boundary would not actually be enforced.
>
> The release pipeline closes this automatically. After `az deployment group create`, the
> **`Enforce API-only-writer boundary`** step in `.github/workflows/release.yml` runs
> [`scripts/cleanup_verify_state_writers.py`](../../scripts/cleanup_verify_state_writers.py) under
> the existing CD OIDC login (keyless — the privileged delete stays in CD, not a script identity):
>
> 1. **Cleanup (idempotent):** at the storage-account scope it deletes every state-store WRITE
>    assignment — Storage **Blob Data Owner** (`b7e6dc6d-f1e8-4753-8033-0f276bb0955b`), Blob Data
>    Contributor, or Table Data Contributor — whose principal is **not** the api identity,
>    then deletes the leftover legacy shared identity resource **only when there is positive evidence
>    it was a state-writer**: its `principalId` must be one of the stray writers just removed at this
>    storage account **and** its name must match the legacy convention `wp-id-<token>` (never the
>    per-component `wp-id-api-*` / `wp-id-worker-*` / `wp-id-web-*` / `wp-id-grafana-*`). A bystander
>    identity an operator happens to name `wp-id-production` / `wp-id-monitoring` that never held a
>    state-write role is therefore **never deleted on name alone**; if a removed stray principal
>    can't be unambiguously correlated to a deletable legacy identity — or a stray assignment has a
>    missing/malformed (non-UUID) `principalId` or missing assignment id — the step **fails closed**
>    (non-zero) rather than silently reporting success, so every stray removed at the account is
>    accounted for. Principal ids are compared with a **single strict UUID normalizer** (stripped +
>    lower-cased) everywhere — allowlist, stray classification and identity correlation — so a
>    whitespace/case variant of an allowed api principal can never be mis-classified stray and
>    have its role deleted. Deletion is also **scope-bound**: a role assignment is only ever deleted
>    when its resource id is a canonical `…/storageAccounts/<sa>/providers/Microsoft.Authorization/`
>    `roleAssignments/<guid>` id under **this** account, and the legacy identity is only deleted when
>    its resource id is a canonical `userAssignedIdentities/<name>` id in the **expected resource
>    group** — a crafted/out-of-scope id fails closed instead of deleting anything foreign. Cleanup
>    only deletes assignments defined **at** the account scope; an assignment inherited from the
>    resource group or subscription cannot be deleted from here. On a fresh environment there is
>    nothing stray, so it is a **no-op**.
> 2. **Verify (fail-closed gate):** it re-lists the assignments **effective** at the storage-account
>    scope (`az role assignment list --scope <SA> --include-inherited`, so a write role inherited
>    from the resource group or subscription is also seen) and **fails the release** if any principal
>    other than the api identity holds a state-write role (Blob Data Owner / Blob Data
>    Contributor / Table Data Contributor) effective there — catching the legacy identity, the worker
>    identity, the web reader identity, or any future regression. For an **inherited** stray it cannot delete, the gate
>    fails with a manual-remediation message naming the principal, role and ancestor scope. Read-only
>    roles (Storage Blob Data Reader `2a2b9908-…`, Storage Table Data Reader `76199698-…`) are
>    deliberately **not** treated as writers. The pure decision logic is unit-tested in
>    `tests/unit/test_state_writer_cleanup.py`; run the gate offline with
>    `--assignments-file <json>` to dry-run it without Azure.
>
> The api principal id and the storage-account id the gate needs are surfaced as
> `main.bicep` outputs (`apiIdentityPrincipalId`, `storageAccountId`) — object ids are not
> credentials, so this stays keyless and in-boundary. (`workerIdentityPrincipalId` is still output for
> telemetry-export's publisher role, not the writer gate — the worker is no longer a state writer.)

## ⚠️ Reader scope: RG-scoped deployment vs subscription-wide discovery

`main.bicep` is `targetScope = 'resourceGroup'`. A resource-group-scoped deployment **cannot** create
a subscription-scope role assignment inline, so `Reader` is granted at the **resource group** — the
narrowest scope this template can assign.

Azure Resource Graph discovery (`AzureResourceGraphClient.query`) reads across a **subscription** (or
management group). With Reader scoped only to this resource group, ARG returns **only the resources
in this resource group**. **Subscription-wide discovery additionally requires a subscription-scope
`Reader` assignment applied separately** — for example:

```bash
az role assignment create \
  --assignee-object-id <wp-id-worker-* principalId> \
  --assignee-principal-type ServicePrincipal \
  --role Reader \
  --scope /subscriptions/<subscription-id>
```

(or an equivalent subscription-scoped Bicep/Terraform deployment). This is deliberately **not** done
here so the template does not silently claim a broader scope than it grants. Network-topology reads
have the same subscription-scope consideration once that client is wired.
