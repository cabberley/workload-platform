# 0003. Runtime composition root wires packs, edge clients and read-only state at the boundary

Date: 2026-08-03 · Status: accepted

## Context

The six modules and their dependencies (the verified packs engine, the keyless Azure/edge clients,
a read-only state view) were built and merged, but they were **no-ops in production**: nothing
injected those dependencies at the process boundary. Concretely:

- `run_module()` built `ModuleContext(state=..., clients=...)` and **dropped `packs` entirely**, so
  `ctx.packs` was always `None` — quality_checks/aiops/dependency_graph never saw any content.
- the API `/api/modules/{name}/run` endpoint injected only a read-only `state` — no packs, no
  clients.
- the worker called `run_module(module, scope=scope)` with **nothing** — no state, packs or
  clients.

Modules are pure by design: they look dependencies up by well-known name (`ctx.packs`,
`ctx.clients["resource_graph"]`, …) and never import a concrete client. Something has to build and
inject those dependencies — a **composition root**.

## Decision

Introduce a single composition root, `src/cli/wiring.py`, as the **only** place allowed to know
concrete pack/edge-client types, and wire it into both entry points:

- `build_packs_engine()` roots a `PacksEngine` at `$WP_CONTENT_ROOT` (default `content`), or
  returns `None` if absent.
- `build_client_registry()` builds the keyless edge clients whose config + SDK are present:
  `resource_graph`, `network`, `notifier`, `system_pulse`. A documented extension hook is left for
  `azure_monitor` (issue #6, not yet on `main`).
- `run_module()` gains a `packs` parameter and forwards it verbatim.
- **API** (`/api/modules/{name}/run`): keeps its fast in-process `ReadOnlyState(store)` and *also*
  injects packs + clients via cached, override-able FastAPI dependencies (`get_packs`,
  `get_clients`) that mirror `get_store`. The API still commits (single writer). Two new read
  endpoints — `GET …/previous-findings` and `GET …/previous-node-ids` — complete the read surface.
- **Worker** (`cli/worker.py`): builds `packs`, `clients`, and a read-only `ApiStateReader`
  (`src/cli/state_client.py`) that implements the full `ReadableState` Protocol over HTTP. It has
  **no write methods**, and the worker still only POSTs its result to the API.

## Consequences

- **+** Packs and edge clients are injected at the boundary, not inside modules — pure logic stays
  Azure-free and unit-testable; `shared` stays decoupled from concrete client types.
- **+** **Single-writer preserved.** The API remains the sole committer; the worker reads through a
  write-less `ApiStateReader`, so there is structurally nothing for it to write with.
- **+** **Keyless / fail-closed / guarded.** Clients authenticate via `DefaultAzureCredential`
  (Managed Identity); only Key Vault-backed env *names/values* are read. A missing SDK, missing
  config, or missing content root leaves the pack/client simply **absent** (module fails closed) —
  no builder ever raises. Every Azure import is lazy/guarded, so importing the composition root
  needs no Azure SDK and `mypy src` stays clean without them installed.
- **+** The `azure_monitor` client (issue #6) drops in as a ~2-line, guarded follow-up at the
  documented extension point.
- **−** One more module (`cli.wiring`) concentrates the concrete-type knowledge; that is deliberate
  — it is the one seam permitted to import edge-client classes.
