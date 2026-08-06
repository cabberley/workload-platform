# Telemetry visualization (Azure Managed Grafana)

The platform visualizes telemetry with **Azure Managed Grafana** over **Azure Monitor** (metrics +
Log Analytics), **in-boundary** and **keyless**. Decision + rationale:
[`adr/0007-telemetry-visualization-managed-grafana.md`](adr/0007-telemetry-visualization-managed-grafana.md).
Infra and provisioning: [`../infra/grafana/README.md`](../infra/grafana/README.md).

## Data-source model (keyless)

- Grafana runs as `Microsoft.Dashboard/grafana` (see `infra/bicep/modules/grafana.bicep`, wired from
  `main.bicep`, which emits `output grafanaEndpoint`).
- It reads Azure Monitor using the **shared user-assigned Managed Identity** from `core.bicep` — the
  same identity used for AcrPull / queues / Key Vault. `apiKey` is **Disabled**: there are **no
  Grafana API keys, service-account tokens, data-source secrets, or connection strings** anywhere.
- **Least-privilege RBAC:** the identity holds only **Monitoring Reader** (metrics) and **Log
  Analytics Reader** (KQL), assigned at **resource-group scope** — the narrowest grant that still
  resolves every baseline panel, with no write/admin anywhere. See the inline rationale in
  `grafana.bicep`.

## Baseline boards (aggregate, PII-free)

Versioned in [`../infra/grafana/dashboards/`](../infra/grafana/dashboards/) as the source of truth:

| Board | What it shows | Status |
|-------|---------------|--------|
| **Module Throughput & Queue Depth** | ACA `Replicas`/`Requests` (service apps), `Executions` (jobs), KEDA queue depth | **Works today** (real ACA metrics) |
| **Workload Health & Node State** | node-state counts and healthy-node ratio | **Requires #86** |
| **Blast Radius & SPOF Summary** | active SPOF count, blast-radius distribution and peak | **Requires #86** |
| **Connector & Telemetry Freshness** | per-connector staleness and fetch success ratio | **Requires #86** |

Every board is **aggregate and PII-free** and uses a `${monitor}` datasource template variable plus
parameterized scope — **no real subscription id, workspace id, resource id, tenant, URL, or token**
is embedded; scope defaults are synthetic placeholders, rebound to your in-boundary signals at
provision time.

### Which boards work today vs require #86

`Module Throughput & Queue Depth` renders **today** from real Azure Monitor **ACA platform metrics**
— it does not depend on any custom telemetry. It splits targets by resource type:
`Microsoft.App/containerApps` (`Replicas`, `Requests`) for the long-running service modules and
`Microsoft.App/jobs` (`Executions`) for the scale-to-zero job modules, plus storage
`QueueMessageCount` for KEDA backlog.

The other three boards read the platform's **intended** Log Analytics custom tables
(`WpNodeState_CL`, `WpSpof_CL`/`WpFinding_CL`, `WpConnectorFetch_CL`), which **nothing emits yet**.
They are versioned **TARGET** boards: they import cleanly but **fail at query time** until the
**#86** telemetry-export path writes those tables. Each is tagged `requires-86` / `target-board` and
carries a board-level description saying so; the custom-table schema is documented in
[`../infra/grafana/README.md`](../infra/grafana/README.md). Nothing here claims these three render
today.

## Embedding in the console (keyless, fail-closed)

Azure Managed Grafana **blocks iframing by default** (`X-Frame-Options` / CSP `frame-ancestors`, no
portal toggle to disable it), and a sandboxed iframe cannot override those response headers. The web
console (`src/web/src/panels/GrafanaPanel.tsx`) therefore behaves as follows:

- **Default — deep-link.** When `VITE_GRAFANA_URL` is set at build time, the console renders an
  **"Open in Azure Managed Grafana"** link that opens the boards in a new tab with **Entra SSO**
  (keyless, `rel="noopener noreferrer"`) — nothing is framed, no token in the URL.
- **Optional — iframe embed.** `VITE_GRAFANA_PANEL_URL` embeds a panel **only** when it points at an
  **embeddable, in-boundary, auth-proxied** panel URL (this repo provisions no such proxy). The
  iframe is **sandboxed** and sends `referrerPolicy="no-referrer"`; still **never a token/API key**.
- **Unset ⇒ fail-closed placeholder.** With neither env set the console shows a documented
  placeholder — never a broken/real embed by default.

The boards behind either path are aggregate and PII-free, so no PHI/PII egresses through the console.

## Guardrails

- **In-boundary** — Grafana and Azure Monitor both live in the customer subscription.
- **Keyless** — Managed Identity only; no keys, tokens, or connection strings.
- **Least privilege** — Monitoring Reader + Log Analytics Reader, RG-scoped; no write/admin.
- **No PHI/PII** — aggregate, synthetic-placeholder boards; sandboxed, no-referrer embedding.
