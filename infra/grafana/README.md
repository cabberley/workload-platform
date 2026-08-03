# Grafana — telemetry visualization (issue #58, ADR 0007)

Azure Managed Grafana is the platform's telemetry surface over **Azure Monitor** (metrics + Log
Analytics), deployed **in-boundary** and accessed **keyless** via Managed Identity. This directory
holds the **versioned baseline dashboards** (the source of truth) and this provisioning note.

- Instance IaC: [`../bicep/modules/grafana.bicep`](../bicep/modules/grafana.bicep) (wired from
  `main.bicep`).
- Decision + rationale: [`../../docs/adr/0007-telemetry-visualization-managed-grafana.md`](../../docs/adr/0007-telemetry-visualization-managed-grafana.md).
- User-facing overview: [`../../docs/telemetry-visualization.md`](../../docs/telemetry-visualization.md).

## Keyless model (what is and isn't automated)

**Automated in Bicep (`grafana.bicep`):**

- The Managed Grafana instance, using the **shared user-assigned Managed Identity** from
  `core.bicep` (the same identity used for AcrPull / queues / Key Vault). `apiKey` is **Disabled** —
  no Grafana API keys or service-account tokens are ever issued.
- **Least-privilege** read role assignments for that identity, scoped to the **resource group**:
  **Monitoring Reader** (metrics) and **Log Analytics Reader** (KQL over the in-boundary
  workspace). No write/admin roles. Scope rationale is documented inline in `grafana.bicep`.

**NOT automated in Bicep (done via the Grafana API, keyless):**

- The **Azure Monitor data source** (a Managed Grafana instance already ships a **built-in**
  `Azure Monitor` data source — we *update* it, never create a duplicate) and the **dashboards**
  below are *not* Bicep child resources — Managed Grafana provisions them through its own API, which
  authenticates against Entra ID. There are therefore **no data-source secrets and no board JSON in
  IaC**.

### Two distinct identities (do not conflate)

- **Data-source (read) identity** — the **shared user-assigned Managed Identity** attached to the
  Grafana instance in `grafana.bicep`. It is used *only at query time* by the Azure Monitor data
  source and holds *only* the RG-scoped **Monitoring Reader** + **Log Analytics Reader** roles. It
  does **not** provision Grafana content and has **no** Grafana Editor/Admin role.
- **Provisioning caller** — a **separate Entra principal** (CI Managed Identity or an operator via
  `az login`) that runs the `az grafana …` commands below. This is the identity that needs a Grafana
  data-plane role.

### Access needed (keyless, via Entra)

The provisioning caller runs `az grafana …` with its **own Entra token** — never a Grafana API key.
It needs the **Grafana Editor** role on the instance to update the data source and import/update
dashboards (assign **Grafana Admin** *only* if you must also manage instance-level settings — least
privilege prefers Editor). This is granted to the **provisioning caller**, not to the shared
data-source identity above. Grant it keyless via an Entra role assignment on the Grafana resource:

```bash
# Grafana Editor (built-in) for the operator/CI principal — keyless, no API key issued.
az role assignment create \
  --assignee-object-id "$PRINCIPAL_OBJECT_ID" --assignee-principal-type ServicePrincipal \
  --role "Grafana Editor" --scope "$GRAFANA_RESOURCE_ID"
```

### Provisioning the data source + dashboards (keyless)

The subscription/workspace/resource-group values below come from the **deployment outputs**
(`grafanaEndpoint` and the core outputs) — they are supplied at deploy time and are **never**
committed. The dashboards ship with only Grafana **template variables** and clearly-synthetic
defaults (e.g. the all-zero subscription GUID, `wp-rg`, `wp-log`); the binding step overwrites those
defaults with the real deploy-time values.

```bash
# Deploy-time inputs (from `az deployment group show ... --query properties.outputs`, never in repo):
GRAFANA_NAME="<from deploy>"          # the Managed Grafana instance name
SUBSCRIPTION_ID="<from deploy>"       # in-boundary subscription id
RESOURCE_GROUP="<from deploy>"        # in-boundary resource group
WORKSPACE_ID="<from deploy>"          # Log Analytics workspace RESOURCE ID (core output logAnalyticsId)
STORAGE_ACCOUNT="<from deploy>"       # queue storage account (core output storageName)

# 1. UPDATE the built-in Azure Monitor data source to authenticate with the instance's Managed
#    Identity (MSI) — do NOT create a second "Azure Monitor" data source (that name collides and
#    fails). No key/secret is supplied here.
az grafana data-source update \
  --name "$GRAFANA_NAME" \
  --data-source "Azure Monitor" \
  --definition '{
    "name": "Azure Monitor",
    "type": "grafana-azure-monitor-datasource",
    "access": "proxy",
    "jsonData": { "azureAuthType": "msi", "subscriptionId": "'"$SUBSCRIPTION_ID"'" }
  }'

# 2. Import each versioned board, RESOLVING its template-variable defaults from the deploy outputs
#    first (sed substitution of the synthetic placeholders into a temp copy under the repo working
#    dir — never committed), then overwrite by uid. NOTE: only module-throughput.json renders today
#    (real ACA metrics); the three Wp*_CL boards require the #86 telemetry-export path (see below).
mkdir -p infra/grafana/.rendered
for f in infra/grafana/dashboards/*.json; do
  out="infra/grafana/.rendered/$(basename "$f")"
  sed -e "s#00000000-0000-0000-0000-000000000000#$SUBSCRIPTION_ID#g" \
      -e "s#resourceGroups/wp-rg#resourceGroups/$RESOURCE_GROUP#g" \
      -e "s#workspaces/wp-log#workspaces/$(basename "$WORKSPACE_ID")#g" \
      -e "s#\"wp-rg\"#\"$RESOURCE_GROUP\"#g" \
      -e "s#wpstsynthetic#$STORAGE_ACCOUNT#g" "$f" > "$out"
  az grafana dashboard import --name "$GRAFANA_NAME" --definition "@$out" --overwrite true
done
```

`az grafana` authenticates with the caller's Entra token; nothing here embeds a Grafana API key,
admin password, or connection string. The `.rendered/` copies hold deploy-time ids and are
git-ignored / never committed — only the templated boards live in the repo. Operators may instead
set the template-variable values interactively in the Grafana UI, or via `az grafana dashboard
update`, if they prefer not to pre-substitute.

The substitution above only rebinds the **scope** placeholders (subscription / resource group /
workspace / storage account). The three `Wp*_CL` boards additionally reference **custom Log
Analytics table names** (`WpNodeState_CL`, `WpSpof_CL`, `WpFinding_CL`, `WpConnectorFetch_CL`) — those
are the platform's *intended* telemetry schema and are **not rebound** here because nothing emits
them yet (see #86 below).

## Which boards work today vs require #86

| Board | Status | Data source |
|-------|--------|-------------|
| `module-throughput.json` | **Works today** | Real Azure Monitor **ACA platform metrics** — `Microsoft.App/containerApps` (`Replicas`, `Requests`) for service modules and `Microsoft.App/jobs` (`Executions`) for job modules, plus storage `QueueMessageCount`. No custom telemetry needed. |
| `workload-health.json` | **Requires #86** | Custom LA table `WpNodeState_CL` (not emitted yet) |
| `blast-radius-summary.json` | **Requires #86** | Custom LA tables `WpSpof_CL`, `WpFinding_CL` (not emitted yet) |
| `telemetry-freshness.json` | **Requires #86** | Custom LA table `WpConnectorFetch_CL` (not emitted yet) |

**#86 — platform telemetry export.** Today the platform emits **no** custom Log Analytics telemetry,
so the three `Wp*_CL` boards are versioned **TARGET** boards: they import cleanly but **fail at query
time** until the [#86](../../docs/telemetry-visualization.md) telemetry-export path writes these
tables. `module-throughput.json` does not depend on #86 and renders as soon as it is bound.

### Intended custom-table schema (target of #86)

The `Wp*_CL` boards expect these Log Analytics custom tables (aggregate, PII-free — no resource ids,
no payloads):

| Table | Columns the boards read |
|-------|-------------------------|
| `WpNodeState_CL` | `Workload_s` (string), `State_s` (`up`/`degraded`/`down`/`unknown`), `TimeGenerated` (datetime) |
| `WpSpof_CL` | `Workload_s` (string), `NodeRef_s` (string, opaque node ref) |
| `WpFinding_CL` | `Workload_s` (string), `BlastRadius_d` (real), `TimeGenerated` (datetime) |
| `WpConnectorFetch_CL` | `Connector_s` (string), `Success_b` (bool), `TimeGenerated` (datetime) |

## Dashboards (parameterized, PII-free)

All boards are **aggregate, PII-free** and **parameterized with Grafana template variables** — a
`${monitor}` datasource variable plus `${subscription}`, `${resourceGroup}`, `${workspace}` /
`${storageAccount}` and per-board scope selectors (`${workload}` / `${serviceModule}` +
`${jobModule}` / `${connector}`). Only **synthetic defaults** ship in the repo (all-zero subscription
GUID, `wp-rg`, `wp-log`, `wpstsynthetic`) — **no real subscription id, workspace id, resource id,
tenant, URL, or token**. Log targets use a proper Azure Monitor Logs `resources: ["${workspace}"]`
shape and metric targets a proper `azureMonitor.resources[]`
(subscription/resourceGroup/resourceName/metricNamespace) shape.

| File | Board | Signals | Status |
|------|-------|---------|--------|
| `dashboards/module-throughput.json` | Module Throughput & Queue Depth | ACA `Replicas`/`Requests` (apps), `Executions` (jobs), queue depth | **Works today** |
| `dashboards/workload-health.json` | Workload Health & Node State | node-state counts, healthy-node ratio | Requires #86 |
| `dashboards/blast-radius-summary.json` | Blast Radius & SPOF Summary | active SPOF count, blast-radius distribution/peak | Requires #86 |
| `dashboards/telemetry-freshness.json` | Connector & Telemetry Freshness | per-connector staleness, fetch success ratio | Requires #86 |

## Embedding in the console

Azure Managed Grafana **blocks iframing by default** (it sets `X-Frame-Options` /
`Content-Security-Policy: frame-ancestors` and does not expose a portal toggle to disable it), so the
console **defaults to a keyless deep-link** ("Open in Azure Managed Grafana", Entra SSO, new tab)
driven by `VITE_GRAFANA_URL`. A true iframe is an **explicitly-optional** path behind
`VITE_GRAFANA_PANEL_URL`, which requires an **embeddable, in-boundary, auth-proxied** panel URL
(never a token). When neither is set the panel fail-closes to a documented placeholder. See
`src/web/src/panels/GrafanaPanel.tsx` and `docs/telemetry-visualization.md`.

## Guardrails

- **Keyless** — Managed Identity only; `apiKey: Disabled`; no data-source secrets in repo or IaC.
- **Least privilege** — Monitoring Reader + Log Analytics Reader, RG-scoped; no write/admin.
- **No PII / no real identifiers** — every board is aggregate and uses synthetic placeholders.
- **In-boundary** — Grafana and Azure Monitor both live in the customer subscription.
