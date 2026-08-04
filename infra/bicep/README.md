# infra/bicep — in-boundary platform IaC

Bicep that provisions the shared, keyless, in-boundary platform (`main.bicep` → `modules/core.bicep`
plus the per-module ACA apps/jobs and Managed Grafana). Everything authenticates with a **single
user-assigned Managed Identity** created in `core.bicep`; there are no keys, connection strings, or
admin credentials anywhere in the templates or their outputs.

## Read-plane RBAC (least privilege, keyless)

All six capability modules share **one** user-assigned identity, so its effective permission set is
the **union** of what each read-plane client needs. Roles are assigned with stable `guid()` names so
the templates are idempotent. Every GUID is verified with
`az role definition list --name "<Role Name>" --query "[0].name" -o tsv`.

| Role | GUID | Scope | Declared in | Consumer(s) | Read vs write | Wired today? |
|------|------|-------|-------------|-------------|---------------|--------------|
| AcrPull | `7f951dda-4ed3-4680-a7ca-43fe172d538d` | Container Registry | `core.bicep` | image pulls (all apps/jobs) | read | ✅ |
| Storage Queue Data Contributor | `974c5e8b-45b9-4653-ba55-5f855dd0fb88` | Storage account | `core.bicep` | KEDA queue scalers + module enqueue/dequeue | read+write | ✅ |
| Key Vault Secrets User | `4633458b-17de-408a-b874-0445c86b69e6` | Key Vault | `core.bicep` | runtime secret reads by identity | read | ✅ |
| **Reader** | `acdd72a7-3385-48ef-bd42-f606fba81ae7` | **Resource group** | `core.bicep` | ARG discovery (`modules/discovery/arg.py`); network topology (`modules/dependency_graph/topology.py`) | read | ARG ✅ · topology ⏳ |
| **Storage Table Data Contributor** | `0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3` | Storage account | `core.bicep` | Azure state backend tables (`shared/state.py` `AzureStateStore`) | read+write | ⏳ |
| **Storage Blob Data Contributor** | `ba92f5b4-2d11-453d-a403-e96b0029c9fe` | Storage account | `core.bicep` | Azure state backend snapshot/estate/graph/findings blobs (`shared/state.py`) | read+write | ⏳ |
| Monitoring Reader | `43d0d8ad-25c7-4714-9337-8ba259a9fe05` | Resource group | `grafana.bicep` | Grafana Azure Monitor data source **and** the Azure Monitor connector metrics edge (`modules/aiops/connectors/azure_monitor.py`) | read | ✅ |
| Log Analytics Reader | `73c42c96-874c-492b-b04d-ab87d138a893` | **Log Analytics workspace** | `grafana.bicep` | Grafana data source **and** the Azure Monitor connector logs edge (`azure_monitor.py`, `LogsQueryClient.query_workspace`) | read | ✅ |

**Bold** rows are the read-plane roles added for issue #80. `✅` = a client that runs in the deployed
topology today; `⏳` = provisioned but the consumer is not yet wired into deployment (see below) —
granting the least-privilege role now keeps the client **fail-closed** rather than fail-open when it
is wired.

### Why write-tier storage data roles

`AzureStateStore` is the API core's single writer. It **creates** the `snapshots`/`workloads` tables
and the state container, writes the manifest entity that is its sole commit point
(`create_entity`/`update_entity`), and uploads the immutable version-scoped estate/graph/findings
blobs (`upload_blob`) as well as reading them back. Because it writes, it needs the **Contributor**
data roles (`Storage Table Data Contributor`, `Storage Blob Data Contributor`), not the read-only
`*Data Reader` variants. `Contributor ⊇ Reader`, so the same grant also covers any read-only
pack-content blob access under this shared identity. The roles are scoped to the **storage account**
(the narrowest inline scope), and account-level `allowSharedKeyAccess` is `false`, so this data-plane
access is keyless (Managed Identity only).

### Monitoring Reader + Log Analytics Reader are not re-declared

The Azure Monitor connector needs Monitoring Reader (metrics) and Log Analytics Reader (KQL over the
in-boundary workspace). Both are **already assigned to this same shared identity** by `grafana.bicep`
(issue #58), so the connector is covered — **Monitoring Reader at resource-group scope** (metrics
span multiple platform resources — Container Apps, storage — not just the workspace) and **Log
Analytics Reader scoped to the single Log Analytics workspace** (the connector's logs edge queries
only that one workspace, `LogsQueryClient.query_workspace`). They are **not** re-declared in
`core.bicep`: a second role assignment for the same principal + role + scope is rejected by Azure
with `RoleAssignmentExists`. The new `Reader` grant also transitively covers the connector's in-RG
reads (`*/read` includes `Microsoft.Insights/*/read` and
`Microsoft.OperationalInsights/workspaces/query/*/read`).

> **Migration note (already-deployed environments):** the Log Analytics Reader assignment was
> previously **resource-group-scoped** and is now scoped to the **workspace**. Changing the scope
> changes the `guid()`-derived assignment name, so a redeploy creates a **new** workspace-scoped
> assignment and leaves the **old RG-scoped one in place** — remove the stale RG-scoped Log Analytics
> Reader assignment for the shared identity during migration. For a fresh private-preview deploy
> there is nothing to migrate.

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
  --assignee-object-id <managed-identity-principalId> \
  --assignee-principal-type ServicePrincipal \
  --role Reader \
  --scope /subscriptions/<subscription-id>
```

(or an equivalent subscription-scoped Bicep/Terraform deployment). This is deliberately **not** done
here so the template does not silently claim a broader scope than it grants. Network-topology reads
have the same subscription-scope consideration once that client is wired.
