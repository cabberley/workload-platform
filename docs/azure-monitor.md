# Azure Monitor connector

The Azure Monitor connector is a second **read-only** telemetry source for the AIOps module
(alongside [System Pulse](connectors.md)). It emits the same PII-safe
[`Signal`](../src/modules/aiops/connectors/system_pulse.py) shape, stamped
`source = SignalSource.azure_monitor`, and is composed from the shared connector base — read-only,
**keyless**, **fail-closed**, bounded, and free of any Azure SDK at import time.

It has **two** independent edges, each guarded/lazy/keyless/fail-closed:

| Edge | SDK (lazy, edge-only) | What it does |
|------|-----------------------|--------------|
| **Metrics** | `MetricsClient` from **`azure-monitor-querymetrics`** | Bounded, read-only metric query over the configured resource ids → normalized `metrics→timeseries→data` payload → `Signal[]`. |
| **Logs** | `LogsQueryClient` from `azure-monitor-query` | Bounded, **aggregated** KQL (counts / averages / percentiles per resource+metric) over a Log Analytics workspace → aggregated numeric `Signal[]`. |

## Why the `azure-monitor-querymetrics` dependency

The metrics client was **split out** of `azure-monitor-query` at 2.0.0 — that package now ships the
**Logs** clients (`LogsQueryClient`) only, and the metrics client (`MetricsClient` /
`query_resources`) moved to the separate **`azure-monitor-querymetrics`** package. The connector
therefore depends on both:

- `azure-monitor-query>=1.4` — the logs edge (already a base dependency).
- `azure-monitor-querymetrics>=1.0` — the metrics edge (added for this connector).

Both are imported **lazily inside the edge methods**, so importing the connector (and hence the API
and worker) never needs an Azure SDK and `mypy src` stays Azure-free. If
`azure-monitor-querymetrics` is not importable at runtime the metrics edge fails closed with the
descriptive class name `AzureMonitorSdkNotWired` (never a misleading `AttributeError`).

## Keyless, Managed-Identity model

The connector never reads a key, secret, or connection string. It takes an **injected
`credential_provider`** — a closure over a keyless `DefaultAzureCredential` built once in the
[composition root](../src/cli/wiring.py). If no credential resolves it fails closed with
`error="NoCredential"` and makes **no** query. The credential object is only ever handed to the SDK
client — never logged or returned.

## No raw-log egress (PII-safe by construction)

The logs edge is guaranteed to emit **only aggregated numeric signals** — never a raw log body,
message, row, or free-text field:

1. **Aggregation-only KQL with FIXED columns.** `build_logs_kql(...)` is a small, pure, reviewable
   transform. The table (`AzureMetrics`) and **every** projected column are **hard-coded, audited
   constants** — never taken from config — so no caller can alias a raw log-body/message column into
   an emitted field or inject an arbitrary KQL identifier. The only config-driven inputs are filter
   *values* (resource ids / metric names, single-quote-escaped) and numeric window/bin sizes. It
   `summarize`s only numeric aggregates (`avg` / `percentile(95)` / `count`) grouped by resource
   id, metric name and a `bin(TimeGenerated, Nm)` bucket, and its final `project` selects **only**
   identifier + numeric-aggregate columns. It never projects a `Body` / `Message` / raw-row column.
2. **Allowlisted normalization.** `_normalize_logs_response(...)` keeps only the allowlisted
   aggregate/identifier columns; any extra column a table might carry is dropped.
3. **Allowlisted mapping.** `map_logs_response(...)` reads only
   `("metric", "value", "unit", "timestamp", "resourceId")` and maps each record through System
   Pulse's `map_signal`, whose `Signal` model is `extra="forbid"`. Any stray field is dropped by
   construction.

This is the same allowlist-based PII safety the System Pulse mapper uses. Unit tests assert that a
record deliberately carrying body/message/free-text columns produces a signal with none of that
content, and that a config attempt to select `Body`/`Message` is rejected outright.

## Endpoint & value hardening (SSRF, injection, non-finite, partial-result)

Additional defences a reviewer can confirm:

* **Trusted metrics endpoint only (SSRF / token-replay).** The metrics client sends a bearer
  Managed-Identity token (scope `https://metrics.monitor.azure.com/.default`) to whatever host it is
  built with, so `_validate_metrics_endpoint(...)` validates the configured
  `AZURE_MONITOR_METRICS_ENDPOINT` **before** any SDK import / client construction: it requires
  `https://`, rejects userinfo, explicit ports, and any path/query/fragment, and requires the host
  to sit under a trusted `*.metrics.monitor.azure.com` / `.azure.us` / `.azure.cn` suffix. A
  non-trusted endpoint fails closed (`error="UntrustedMetricsEndpoint"`) with **no token minted**.
* **No KQL identifier injection.** Because the table/columns are fixed constants and only quoted
  string *values* are interpolated (single quotes doubled), a configured resource id / metric name
  can never break out of its literal.
* **SUCCESS-only logs results.** Only a `LogsQueryStatus.SUCCESS` result is normalized; a `PARTIAL`
  (or missing/unexpected) status fails closed rather than being reported as a successful-empty
  all-clear.
* **Non-finite values dropped.** `map_signal` rejects `NaN` / `±inf`, so a malformed metric/log
  aggregate is dropped like any other bad point (never silently bypassing thresholds or fabricating
  a breach).
* **Bounded timeout across retries.** The configured `timeout_s` is forwarded to both SDK calls
  (`server_timeout` for logs, `timeout` for metrics) so a query cannot exceed its bound.
* **Complete metrics config required.** The real metrics edge runs only when `resource_ids` **and**
  `AZURE_MONITOR_METRICS_ENDPOINT` **and** `AZURE_MONITOR_METRIC_NAMESPACE` are all present, so a
  logs-only deployment that sets `resource_ids` merely to bound its KQL does not trip a broken
  metrics edge.

## Least-privilege RBAC

Request the **narrowest** role that works, scoped as tightly as possible (prefer the specific
workspace / resource group over the subscription):

| Edge | Role | Rationale |
|------|------|-----------|
| Metrics | **Monitoring Reader** | Read-only access to Azure Monitor metrics and monitoring settings. It is the minimum built-in role that can read platform metrics for the queried resources; it grants no write/remediation rights. |
| Logs | **Log Analytics Reader** (or **Reader** on the workspace) | Read-only query access to Log Analytics data. It permits running the aggregated KQL against the workspace but not editing/deleting data, saved searches, or the workspace itself. |

Both roles are read-only — consistent with the platform guardrail that connectors never write to or
remediate customer infrastructure.

## Configuration (env var **names** only — values are Key Vault-backed / identity-supplied)

The [composition root](../src/cli/wiring.py) registers the connector as the `"azure_monitor"`
client **only when** `AZURE_MONITOR_WORKSPACE_ID` **and** a keyless credential are both present. A
missing workspace/credential/SDK leaves the key **absent**, so the AIOps module fails closed on
lookup.

| Env var | Required? | Purpose |
|---------|-----------|---------|
| `AZURE_MONITOR_WORKSPACE_ID` | **Yes** — gates registration | Log Analytics workspace id (GUID) for the aggregated logs edge. |
| `AZURE_MONITOR_RESOURCE_IDS` | Optional | Comma-separated Azure resource ids; enables the metrics edge and bounds both edges. |
| `AZURE_MONITOR_METRICS_ENDPOINT` | For metrics | Regional metrics data-plane endpoint, e.g. `https://westus3.metrics.monitor.azure.com` (queried resources must be in the same region + subscription). |
| `AZURE_MONITOR_METRIC_NAMESPACE` | For metrics | Metric namespace containing the requested metric names. |

Only the env var **names** live in code; their values are supplied at runtime by identity / Key
Vault (keyless). No secret, key, or connection string is ever read or embedded.

## Testing

Driven entirely by the synthetic-payload harness in
[`tests/support/connectors.py`](../tests/support/connectors.py) with injected fake metrics/logs
backends — no real SDK, no network, no Azure credentials. See
[`tests/unit/test_azure_monitor.py`](../tests/unit/test_azure_monitor.py) (pure mapping, aggregated
logs, no-raw-body proof, fail-closed edges, wiring) plus the metrics coverage in
[`tests/unit/test_aiops.py`](../tests/unit/test_aiops.py) and
[`tests/unit/test_connector_base.py`](../tests/unit/test_connector_base.py).
