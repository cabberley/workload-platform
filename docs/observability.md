# Platform self-observability

The platform observes **itself** so operators can run it confidently: liveness/readiness health,
lightweight internal metrics, and vendor-neutral tracing seams across the API core, modules and
workers. This is cross-cutting infrastructure and lives in `src/shared/observability.py` (used by
the API core and service entrypoints) — no capability module imports another to provide it.

Everything here honours the guardrails: **in-boundary, keyless, fail-closed, no PII in telemetry.**
Telemetry carries only **low-cardinality names + numeric measures** — never a secret, connection
string, resource id, or PII.

## Endpoints

| Endpoint | Kind | Purpose |
|----------|------|---------|
| `GET /api/health` | **Liveness** | True while the process is up; **never** depends on external dependencies. |
| `GET /api/health/ready` | **Readiness** | Reflects real dependencies; **fails closed** (HTTP 503) if any is not verified ready. |
| `GET /api/metrics` | Metrics | Read-only, keyless JSON snapshot of the in-process metrics registry. |

### Liveness — `GET /api/health`

Preserves its existing shape exactly (the compose-smoke CI gate parses `status`, `service`,
`modules`) and adds only-additive fields:

```json
{
  "status": "ok",
  "service": "workloads-platform-api",
  "modules": [{ "module": "discovery", "status": "ok" }],
  "live": true,
  "kind": "liveness"
}
```

Liveness reaching its handler is itself the proof the process is serving. It must **not** call the
state store or any dependency, so a slow/unreachable dependency can never trigger an unnecessary
restart loop. Dependency readiness is a separate endpoint.

### Readiness — `GET /api/health/ready`

Probes each dependency at the I/O edge and folds the results with the **pure**
`aggregate_readiness`. Returns `200` when ready, **`503` when not** — always with a structured
per-dependency breakdown (`ReadinessReport`):

```json
{
  "ready": true,
  "dependencies": [
    { "name": "state_store",  "ok": true,  "detail": "reachable" },
    { "name": "packs_engine", "ok": true,  "detail": "absent" },
    { "name": "edge_clients", "ok": true,  "detail": "constructed (0 clients)" }
  ]
}
```

What each dependency checks:

- **`state_store`** — a cheap, **backend-agnostic** reachability read through the `StateStore`
  interface (`list_workloads`), so it works for both the local and Azure backends without coupling
  to either. Any error ⇒ not ready.
- **`packs_engine`** — built/verified, or **intentionally absent** (no content root). Absent is a
  deliberate, ready state (modules fail closed on `packs=None`); an unexpected inspection error ⇒
  not ready.
- **`edge_clients`** — the keyless edge-client registry was constructed (a mapping). Missing ⇒ not
  ready. (We never *connect* a client during readiness — that would be side-effecting I/O.)

**Fail-closed** means: readiness is `True` only when **every** probed dependency is *positively*
verified ready (and at least one was probed). An errored or unknown probe leaves its `ok` false,
which forces `ready: false` → HTTP 503. Every `detail` is a short, bounded, non-sensitive string —
exceptions (which could carry a connection string) are deliberately **not** echoed.

### Metrics — `GET /api/metrics`

A vendor-neutral JSON snapshot (`MetricsSnapshot`) — deliberately **not** Prometheus text, and
keyless:

```json
{
  "counters": [
    { "name": "module_runs_total", "labels": { "module": "discovery", "outcome": "ok" }, "value": 3 },
    { "name": "connector_fail_closed_total", "labels": { "module": "aiops" }, "value": 1 }
  ],
  "durations": [
    { "name": "module_run_duration_ms", "labels": { "module": "discovery", "outcome": "ok" },
      "count": 3, "totalMs": 42.0, "minMs": 8.0, "maxMs": 20.0 }
  ]
}
```

## Metrics tracked

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `module_runs_total` | counter | `module`, `outcome` (`ok`/`error`) | recorded at the API `/api/modules/{name}/run` boundary |
| `module_run_duration_ms` | duration (count/total/min/max) | `module`, `outcome` | same boundary |
| `connector_fail_closed_total` | counter | `module` | injectable observer seam: `shared.connectors.fail_closed(observer=…)` → `record_connector_fail_closed` |

**Avoiding PII / high cardinality:** metric labels are strictly bounded to a **module name** and a
**fixed outcome vocabulary** — no resource ids, no connection strings, no free text. The domain
helpers (`record_module_run`, `record_connector_fail_closed`) only ever emit those bounded labels,
which is the sanctioned low-cardinality shape. Durations store only aggregates (count + sum +
min/max), never per-event rows, so nothing request-identifying is retained. The registry is
in-process, keyless, and thread-safe (a coarse lock — the API is a low-replica single writer).

## Tracing seam (no vendor lock, keyless)

`Tracer` is an OpenTelemetry-**style** seam wired at two edges:

- **API request boundary** — a middleware wraps each request in an `http.request` span with
  **PII-free** attributes: HTTP method, the matched **route template** (`/api/workloads/{workload}/
  findings` — parameter *names*, never values) and the numeric status code.
- **Module run boundary** — the `/api/modules/{name}/run` endpoint wraps the run in a `module.run`
  span (attributes: `module`, `outcome`) — never reaching inside the module.

The default is a **no-op**: with no exporter wired, the only work is creating a span object and
reading a monotonic clock — **no network, no secret, nothing exported**. The export call is guarded
so a broken exporter can never break the traced request path. There is **no hard dependency** on an
OTel exporter or any network export by default.

> `TODO(human):` choose the concrete, keyless exporter (e.g. an OTLP exporter over Managed Identity
> to an in-boundary collector, or an Azure Monitor exporter) and wire it as the `Tracer`'s
> `exporter` at the composition root. Keep it off by default and never read a key/connection string
> in code.

## Keyless / no-PII stance (summary)

- **Keyless.** Nothing here reads a secret or connection string. Any concrete tracing exporter must
  authenticate with Managed Identity, wired at the composition root.
- **No PII / no raw identifiers in telemetry.** Only low-cardinality names + numeric measures.
  Readiness `detail`s are fixed, non-sensitive strings; metric labels are bounded; span attributes
  carry method/route-template/outcome only.
- **Fail closed.** Readiness reports NOT ready on any unknown/errored dependency (HTTP 503).
  Liveness is independent of dependencies. Probes swallow exceptions into a not-ready result rather
  than crashing.
- **Pure logic ⟂ I/O.** `aggregate_readiness`, the metrics registry math, and
  `build_metrics_snapshot` are pure and unit-tested; the probes/exports are thin edges.
