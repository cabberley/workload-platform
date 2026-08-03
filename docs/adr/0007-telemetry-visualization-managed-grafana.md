# 0007. Telemetry visualization on Azure Managed Grafana (keyless, in-boundary, no-PII)

Date: 2026-08-04 · Status: accepted

## Context

The platform needed a decision on its **telemetry visualization surface**: how operators see
workload health, blast-radius/SPOF summaries, module throughput, and connector/telemetry freshness.
Some signals already live **in-boundary** in **Azure Monitor** today — **ACA platform metrics**
(replicas/requests/CPU, KEDA queue depth) from Container Apps/Jobs — so those render immediately. The
**app-signal** boards (workload health, SPOF/blast-radius, connector freshness) instead depend on
the platform's **intended** Log Analytics custom tables
(`WpNodeState_CL`/`WpSpof_CL`/`WpFinding_CL`/`WpConnectorFetch_CL`), which are **not emitted yet** and
require the telemetry-export path **#86** before those three target boards render. Either way the
question here was only *what renders them*. Issue #58 was gated on a single open choice recorded as a
`TODO(human)` in `src/web/src/panels/GrafanaPanel.tsx` and `docs/README.md`: **Azure Managed Grafana
vs Azure Monitor Workbooks**.

Constraints from the guardrails (`.github/copilot-instructions.md`, `ARCHITECTURE.md`):

- **In-boundary only** — the surface and its data plane must stay in the customer subscription.
- **Keyless** — Managed Identity via `DefaultAzureCredential`; no API keys, admin tokens, or
  connection strings in code, config, or the web bundle.
- **Least privilege** — the narrowest read RBAC that works, documented.
- **No PHI/PII** — dashboards, fixtures, and embedding must expose aggregate, PII-free data only.
- **Fail closed** — an unconfigured console panel must show a placeholder, never a broken/real embed.

`ARCHITECTURE.md` already names *Azure Managed Grafana + workbooks* as the dashboard technology, and
the web panel + build-time env `VITE_GRAFANA_PANEL_URL` were scaffolded ahead of this decision.

## Decision

Adopt **Azure Managed Grafana** as the telemetry visualization surface, reading **Azure Monitor**
(metrics + Log Analytics) **keyless** via Managed Identity, with **no-PII** boards and keyless,
**auth-proxied** console embedding.

- **Surface = Azure Managed Grafana** (`Microsoft.Dashboard/grafana`), provisioned in
  `infra/bicep/modules/grafana.bicep` and wired from `main.bicep` (with an `output grafanaEndpoint`).
- **Data source = Azure Monitor**, authenticated by the **shared user-assigned Managed Identity**
  from `core.bicep` (the same identity used for AcrPull / queues / Key Vault). The instance sets
  `apiKey: 'Disabled'` — no Grafana API keys or service-account tokens exist.
- **Least-privilege roles.** The identity is granted only **Monitoring Reader** (metrics) and
  **Log Analytics Reader** (KQL over the in-boundary workspace), assigned at **resource-group
  scope**. Rationale: the entire in-boundary platform and the signals the baseline boards query live
  in that one resource group, so RG scope is the narrowest grant that still resolves every panel; it
  confers no access outside the RG and **no write/admin** role (no Grafana Admin, no Monitoring
  Contributor). A cross-RG workspace, if ever needed, gets its own explicitly-scoped assignment
  rather than widening this one.
- **Dashboards are versioned content, provisioned via the Grafana API.** Managed Grafana creates the
  data source and dashboards through its own Entra-authenticated API, not as Bicep child resources —
  so **no data-source secret and no board JSON live in IaC**. The baseline boards are versioned in
  `infra/grafana/dashboards/` as the source of truth and imported keyless (`az grafana … import`
  with an Entra token); see `infra/grafana/README.md`.
- **No-PII boards.** Baseline boards (workload health/node-state, blast-radius/SPOF summary, module
  throughput & queue depth, connector/telemetry freshness) show **aggregate** data only and use a
  `${monitor}` datasource template variable plus parameterized scope — **never** a real subscription
  id, workspace id, resource id, tenant, URL, or token; scope defaults are synthetic placeholders
  rebound at provision time.
- **Current vs target boards (requires #86).** Only **`module-throughput`** renders **today**: it
  reads **real Azure Monitor ACA platform metrics** — `Microsoft.App/containerApps` (`Replicas`,
  `Requests`) for the service modules and `Microsoft.App/jobs` (`Executions`) for the job modules
  (split into separate panels because they are different resource types), plus storage
  `QueueMessageCount`. The other three boards query the platform's **intended** Log Analytics custom
  tables (`WpNodeState_CL`, `WpSpof_CL`/`WpFinding_CL`, `WpConnectorFetch_CL`) which **nothing emits
  yet** — they are versioned **TARGET** boards that import but fail at query time until the **#86**
  telemetry-export path writes those tables. Each such board is labelled `requires-86` /
  `target-board` and carries a board-level description stating this; the table schema is documented in
  `infra/grafana/README.md`. This is an honest current-vs-intended split, not a claim that all four
  render today.
- **Keyless, fail-closed embedding — deep-link by default.** Azure Managed Grafana **blocks iframing
  by default** (it returns `X-Frame-Options` / CSP `frame-ancestors` and exposes no portal toggle to
  disable it), and a sandboxed iframe cannot override those response headers. The console therefore
  **defaults to a keyless deep-link** — an "Open in Azure Managed Grafana" link (new tab, Entra SSO)
  driven by the build env `VITE_GRAFANA_URL`. A true iframe embed is an **explicitly-optional** path
  behind `VITE_GRAFANA_PANEL_URL`, which requires an **embeddable, in-boundary, auth-proxied** panel
  URL (never a token in the URL); this repo provisions no such proxy. When neither env is set the
  panel shows a documented placeholder (fail-closed). Both the deep-link (`rel="noopener noreferrer"`,
  `target="_blank"`) and the optional iframe (sandboxed, `referrerPolicy="no-referrer"`) keep the
  security posture; no URL or token is hardcoded in the bundle.

## Alternatives considered

- **Azure Monitor Workbooks.** Native to Azure Monitor, no extra resource to run, and keyless via
  RBAC. Rejected as the primary surface because: (1) **embedding** a Workbook cleanly and keyless in
  the in-boundary SPA is awkward (portal-centric; auth-proxied panel embedding is weaker than
  Grafana's `d-solo` panels); (2) **operational ergonomics** — Grafana gives richer templating,
  alerting, and a dashboards-as-code JSON model we can version in-repo as the source of truth; (3)
  **cost/ops trade-off** — Workbooks add no run cost, but Managed Grafana's flat instance cost buys
  the embedding + dashboards-as-code + multi-source story the console needs. Workbooks remain a
  sanctioned *complement* for deep ad-hoc Azure Monitor exploration (consistent with
  `ARCHITECTURE.md`'s "Managed Grafana + workbooks"), not the embedded console surface.
- **Self-hosted Grafana (OSS) in a container.** More operational burden (patching, identity, TLS)
  and no managed Entra/Managed-Identity integration out of the box. Rejected — Managed Grafana is the
  keyless, in-boundary managed option.

## Consequences

- **Keyless end to end.** Instance → Azure Monitor uses Managed Identity; `apiKey` disabled; the web
  bundle carries only an optional auth-proxied URL. Reviewers can grep IaC/bundle for keys/tokens and
  find none.
- **Least privilege is explicit and auditable.** Exactly two RG-scoped read roles; the scope choice
  is documented inline in `grafana.bicep` and here.
- **Dashboards-as-code.** Boards live in `infra/grafana/dashboards/` and are the source of truth;
  provisioning is honestly documented as a keyless Grafana-API step (not a Bicep child resource).
- **No-PII invariant.** Boards are aggregate and use synthetic placeholders; the embed path is
  sandboxed/no-referrer and the default deep-link opens Managed Grafana out-of-page (Entra SSO). The
  console shows a placeholder when unconfigured.
- **`#58` decision closed.** The `TODO(human)` "Grafana vs Workbooks" is removed from the web panel;
  `docs/README.md` and `docs/telemetry-visualization.md` reflect the resolved decision.
