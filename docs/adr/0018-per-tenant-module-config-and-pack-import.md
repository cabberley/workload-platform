# 0018. Per-tenant module enable/disable + custom pack import — tenant-namespaced config & import records, deny-by-default visibility, fail-closed enforcement

Date: 2026-08-22 · Status: accepted

## Context

[ADR 0017](0017-tenant-isolation-model.md) (issue #65) made the platform tenant-isolated: every
request resolves exactly one [`TenantContext`](../../src/api/app/tenancy.py) at the API boundary
(fail closed), and [`TenantScopedState`](../../src/api/app/tenant_state.py) namespaces every state
write and filters every read by a **tenant partition key** on BOTH backends (the local sqlite
`LocalStateStore` and the Azure Table+Blob `AzureStateStore` in
[`src/shared/state.py`](../../src/shared/state.py)). It already tenant-scopes pack **assignments**.

Two capabilities built before the isolation model are still **process-wide** and would leak across
tenants in a `multi` overlay:

1. **Module enablement.** A capability module's `enabled` flag lives on its platform-wide
   [`ModuleManifest`](../../src/shared/contracts.py); `GET /api/modules` returns the one shared
   catalogue and there is no per-tenant enablement — every tenant sees and can run the same modules.
2. **Custom pack import.** `POST /api/packs/import` verifies a signed pack and publishes it into a
   **process-wide** [`PackRegistry`](../../src/packs_engine/registry.py) visible to everyone, so an
   imported pack — potentially a customer's own custom rules — would be visible to, and runnable by,
   **every** tenant on the instance. `GET /api/packs` lists that shared registry; pack **assignment**
   binds against it.

Issue #68 asks for both to be **per-tenant**, mirroring the ADR 0017 precedent, without regressing
the single-tenant default and without weakening the keyless, signed-pack, fail-closed guarantees of
[#89](../../src/packs_engine/) (import trust root) and [#44](../../src/packs_engine/content_store.py)
(digest-addressed content store).

## Decision

**Persist per-tenant module-enablement config and per-tenant imported-pack ownership records
tenant-namespaced (same partition-key precedent as pack assignments), enforce module disablement
fail-closed at BOTH the read and execute surfaces, and scope pack visibility/assignment
deny-by-default so a pack imported by one tenant is invisible and unusable to every other tenant —
while keeping identical pack BYTES deduplicated in the shared, content-addressed store.**

### 1. Contracts — additive, internal storage models — `src/shared/contracts.py`

Two additive Pydantic models, each carrying an internal-only `scope` (the tenant-namespace carrier,
threaded by `TenantScopedState` exactly like [`PackAssignment.workload`](../../src/shared/contracts.py)
— **never egressed**):

- [`ImportedPack`](../../src/shared/contracts.py) — the per-tenant OWNERSHIP/visibility index for a
  signed pack a tenant imported: `packId`/`version`/`packType`, the content-address `digest` (the key
  into the shared content store), the VERIFIED detached `signature` + `keyId` (serialized exactly as
  the registry persists them, so the runtime can independently re-verify trust), and `importedBy`/
  `importedAt` provenance. The pack BYTES are **not** stored here.
- [`TenantModuleConfig`](../../src/shared/contracts.py) — a tenant's `disabled` module-name set.
  **Deny-by-default is deliberately NOT applied to modules:** a tenant with no config keeps today's
  default-enabled catalogue (existing single-tenant deployments are unchanged); only an explicit
  disable flips a module off. Module names are static platform identifiers (never PII).

### 2. `StateStore` Protocol + BOTH backends — `src/shared/state.py`

The [`StateStore`](../../src/shared/state.py) Protocol gains scope-carrying, single-writer methods
implemented on BOTH backends, mirroring the existing pack-assignment methods:

- `put_imported_pack` / `try_record_imported_pack` (atomic insert-if-absent-else-verify-digest) /
  `get_imported_pack(scope, pack_id, version)` / `list_imported_packs(scope)`;
- `get_module_config(scope)` / `put_module_config(config)`.

`LocalStateStore` adds an `imported_packs` table (PK `scope,pack_id,version`) and a `module_config`
table (PK `scope`), each written in one transaction with replace-on-conflict semantics.
`AzureStateStore` adds an `importedpacks` table (RowKey = encoded `packId\x00version`, upsert
replace) and a `moduleconfig` table (one entity per scope), created in `from_env` alongside the
existing tables. The raw store lists every record; the **tenant filter lives in the facade** (below).

### 3. Tenant-scoped facade methods — `src/api/app/tenant_state.py`

[`TenantScopedState`](../../src/api/app/tenant_state.py) adds natural-signature convenience methods
that thread the tenant partition key, following the ADR 0017 pattern (**namespace on write, filter
deny-by-default on read, restore the logical value so the tenant prefix never surfaces**):

- **Imported packs** — `record_imported_pack`, `try_record_imported_pack` (atomic, delegates to the
  backend guard), `get_imported_pack(pack_id, version)`, `list_imported_packs()` (passes its own
  `_imports_scope()` so the backend filters by scope — see §6.4). The physical `scope` is derived
  from a **reserved internal workload name** `"_imports"` fed through `tenant_partition_key`, so two
  tenants importing the same `id@version` write to DISJOINT physical keys and `list_imported_packs()`
  keeps only rows whose [`workload_of`](../../src/api/app/tenancy.py) resolves to `"_imports"` for
  THIS tenant (another tenant's key yields `None` and is dropped).
- **Module config** — `get_module_config()`, `get_disabled_modules()`, `set_disabled_modules()`,
  namespaced via the reserved name `"_modules"`.

These reserved names live in the SAME composite-key space as real workloads, so isolation is the same
mechanism proven for assignments — no new isolation primitive.

### 4. Pack architecture — shared bytes, per-tenant ownership — `src/packs_engine/`

Import no longer publishes to the process-wide registry. Instead:

- The verified pack BYTES are materialized into the **shared, digest-addressed content store**
  ([#44](../../src/packs_engine/content_store.py)) — content-addressed, so identical bytes dedupe
  across tenants and a content hash reveals nothing about a tenant.
- OWNERSHIP/visibility is recorded per-tenant via `record_imported_pack`.

At run time the API builds a per-tenant registry view — [`InMemoryPackRegistry`](../../src/packs_engine/registry.py)
(a new `PackRegistryReader`-Protocol implementation) of the BUILT-IN/shared entries **plus THIS
tenant's imports** — and hands it to the engine via the new
[`PacksEngine.with_import_registry`](../../src/packs_engine/engine.py) (a shallow clone that swaps
only the registry used by `_resolve_imported_packs`, sharing the content root, trust root, and
content store). Another tenant's imports are simply not in that view, so they can never be resolved
or executed. Each imported pack is still **independently re-verified against the pinned trust
bundle** before use — the #89 runtime trust boundary is unchanged.

### 5. API surface — read + execute enforcement — `src/api/app/main.py`

- `GET /api/modules` — returns the caller tenant's EFFECTIVE catalogue: a module the tenant has
  disabled is reported `enabled=False`. The projection reads the tenant-scoped disabled set.
- `GET /api/modules/config` (reader) / `PUT /api/modules/config` (operator) — get/replace the
  tenant's disabled set. `PUT` rejects an unknown module name **422 fail closed** (a typo can never
  disable nothing or persist a phantom id) and AUDITS each enable/disable transition BEFORE the write
  ([ADR 0014](0014-fail-closed-audit-emission.md)).
- `POST /api/modules/{name}/run` — a module the caller's tenant has disabled fails closed with a
  **fixed 403 reason code BEFORE any resolve/run/audit/write**, so a disabled module can never
  execute or mutate state for that tenant.
- `GET /api/packs` — returns the union of built-in/shared registry entries and THIS tenant's own
  imports, de-duplicated by ref; never another tenant's imports.
- `POST /api/packs/import` (operator) — verifies the signature against the shared pinned trust root
  (unchanged), rejects a `pack_id` reserved by any built-in/shared pack (**409**, disjoint id-space —
  see §6.3), then materializes bytes to the shared content store and records per-tenant ownership via
  the ATOMIC `try_record_imported_pack` (see §6.2). Immutability is enforced **per tenant**:
  re-importing the same `id@version` with different content is a **409**; identical content is
  idempotent (**200**, existing entry returned).
- `PUT /api/workloads/{workload}/pack-assignments` — the pack `id@version` must be VISIBLE to the
  caller's tenant: the SHARED registry is checked FIRST, else the tenant's own import; a pack the
  tenant cannot see is **422 fail closed**, so a pack imported by another tenant can never be
  assigned. (Order is immaterial once ids are disjoint — see §6.3 — but is kept SHARED-FIRST for
  consistency with the catalogue and runtime precedence.)

The response models egress only static, non-PII data (`ModuleConfigView.disabled` is module names;
`PackRegistryEntryView` is unchanged), so the no-PII-egress auditor stays green with no new waiver.
`ImportedPack`/`TenantModuleConfig` are internal storage models and are never egressed.

### Why a per-tenant registry view, not a per-tenant registry on disk

The engine resolves imports from ONE `_registry`. Rather than fork the durable registry per tenant
(and duplicate the shared/built-in entries), the API composes an in-memory view (shared entries +
this tenant's imports) per run and hands it to a shallow engine clone. The durable process-wide
`PackRegistry` now holds only built-in/shared packs; per-tenant state holds ownership; the shared
content store holds bytes. This keeps the isolation boundary in the tenant-scoped store (the proven
#65 mechanism) and the trust boundary in the unchanged #89 re-verification.

### 6. Adversarial-review hardening (issue #68 R2)

An adversarial review (gpt-5.6-sol) surfaced four gaps between the guarantees claimed above and the
implementation; all are now closed. These are load-bearing for the fail-closed / deny-by-default
posture and are documented here so the invariants are not silently regressed.

**6.1 Module toggles are fail-closed on an audit-store OUTAGE, not just an unconstructable event.**
`PUT /api/modules/config` audits each enable/disable transition BEFORE the write ([ADR 0014](0014-fail-closed-audit-emission.md)),
but `module.enabled`/`module.disabled` were absent from
[`shared.audit.FAIL_CLOSED_ACTIONS`](../../src/shared/audit.py), so a durable-append OUTAGE (sink
raises) was swallowed best-effort and the config write proceeded UNAUDITED — contradicting the
`put_module_config` contract. `AuditAction.module_enabled`/`module_disabled` are now in
`FAIL_CLOSED_ACTIONS`: a config/posture change must be DURABLY audited before it commits, so an audit
outage yields a 5xx and the disabled-set is left unchanged. The remaining best-effort-on-outage
allowance is now exactly the `pack.verify` FAILURE breadcrumb (emitted mid-pack-load, where raising
would turn a safe rejection into a crash) plus `pack.import`/`pack.assign` (the deliberate,
documented issue-#99 platform allowance) — not module toggles.

**6.2 Per-tenant version immutability is ATOMIC (no read-then-write TOCTOU).** The immutability guard
was a non-atomic `get_imported_pack` pre-check followed by an unconditional upsert
(`ON CONFLICT DO UPDATE` / `upsert_entity(replace)`), so two concurrent imports of the same
`(scope, packId, version)` with DIFFERENT digests could both pass the pre-check and last-writer-wins.
A new backend operation `try_record_imported_pack` makes the check+insert atomic on BOTH backends and
is now the sole authority (the API keeps only a fast-path read for a friendly early 409):
- **sqlite:** one `BEGIN IMMEDIATE` write transaction runs `INSERT … ON CONFLICT(scope,pack_id,version) DO NOTHING`;
  the INSERT itself is the atomic guard. `rowcount == 1` ⇒ inserted; `0` ⇒ conflict, then SELECT the
  existing row and compare digest — same ⇒ idempotent (return stored), different ⇒ raise
  `ImportConflictError`.
- **Azure Table:** `create_entity` (atomic; raises `ResourceExistsError` when the row exists) REPLACES
  `upsert_entity(replace)`; on conflict, `get_entity` + digest compare — same ⇒ idempotent, different
  ⇒ `ImportConflictError`.
`POST /api/packs/import` maps `ImportConflictError` to **409** ("immutable version conflict (fail
closed)") and the idempotent same-digest case to a normal **200** returning the existing entry. The
`pack.verify` audit and `content_store.put(digest, bytes)` (idempotent by digest) run BEFORE the
atomic record; the `pack.import` SUCCESS audit runs only AFTER a non-conflict record. The FIRST
content is therefore never overwritten.

**6.3 Tenant imports occupy a DISJOINT id-space from shipped/shared packs (reserved-id admission).**
Three surfaces previously disagreed on precedence, and the runtime resolver already SKIPS any imported
entry whose id is a shipped id (shipped-wins-by-id, an airtight MERGED invariant in
[`engine.py`](../../src/packs_engine/engine.py)). Net bug: a tenant could import AND assign a pack
whose id collided with a shipped/shared pack — the assignment succeeded but the runtime resolved
NOTHING (a successful-but-unusable assignment). Fixed by reserving the shipped/shared id-space at
import admission: `POST /api/packs/import` rejects a colliding `pack_id` with **409** ("import
rejected: pack id reserved by a platform pack (fail closed)") BEFORE any record. The reserved set is
built ENGINE-INDEPENDENTLY as the UNION of (a) the SHARED on-disk registry ids —
`{e.ref.id for e in packs_registry.list()}`, always available and the same set `put_pack_assignment`
consults — and (b), when a `PacksEngine` is wired, its
[`reserved_pack_ids()`](../../src/packs_engine/engine.py) (the content-root shipped-manifest ids).
Reading the shared registry directly means a shared id stays reserved even when NO engine is wired
(MED-1). With the id-space
disjoint, precedence is immaterial, but catalogue de-dup, assignment lookup, and the runtime view are
all kept SHARED-FIRST for clarity. A tenant import can therefore never become an unusable assignment.

**6.4 The imported-pack backend list is scope-filtered at the storage layer.** `list_imported_packs`
returned EVERY tenant's rows (sqlite full-table `SELECT`, Azure `list_entities`) and relied on the
facade to filter afterward, so every catalogue read and module run scaled with ALL tenants' imports
(one tenant's volume degraded others). The signature is now `list_imported_packs(scope)`: sqlite
filters `WHERE scope = ?`, Azure `query_entities` with a `PartitionKey eq <encoded scope>` filter.
`TenantScopedState.list_imported_packs` passes its own `_imports_scope()`, and the cheap in-facade
`workload_of(...) == "_imports"` check is retained as defense-in-depth. (The pre-existing
`list_pack_assignments` full-scan is untouched merged #65 behaviour, out of scope for #68.)

## Backward-safety (pre-GA / greenfield)

- **Modules default-enabled:** a tenant with no `TenantModuleConfig` behaves exactly as today, so a
  single-tenant deployment is unchanged. Only an explicit disable changes behaviour.
- **New state only:** the `imported_packs`/`module_config` tables are additive; no migration of
  existing state is required. Existing pack **assignments** are unaffected.
- **Import behaviour change:** imports no longer land in the process-wide registry. This is the
  intended isolation fix; the only affected surface was the previously-shared visibility, which was a
  cross-tenant leak in a `multi` overlay. Existing integration tests that asserted post-import
  registry publication were updated to assert per-tenant visibility instead.

## Consequences

- **+** Deny-by-default cross-tenant isolation for BOTH module config and imported packs: no code
  path lets tenant A read, use, or influence tenant B's module config or imports; the tenant prefix
  never surfaces to callers.
- **+** Fail-closed enforcement at the execute surface: a disabled module is a fixed-reason 403
  before any run/write; an invisible pack is a 422 before any assignment write.
- **+** Signed packs stay verified before use (import admission AND independent runtime
  re-verification against the pinned bundle); keyless throughout; identical bytes deduped in the
  shared content store (per-tenant scoping is visibility/ownership, not byte duplication).
- **+** Module isolation preserved: capability modules keep their read-only surface; the API core is
  the single writer; the `StateStore`/`ReadableState` Protocol signatures the modules consume are
  unchanged (the new methods are additive and the facade's convenience methods sit above them).
- **−** Per-tenant module config and imports inherit ADR 0017's known limitations: the tenant hex
  prefix appears inside the physical key (only the owning tenant observes its own key), and the
  overlay worker-context and IaC env-threading follow-ups (#122/#123) still gate production `multi`
  use.
- **−** The durable registry and the per-tenant import view are composed at run time; a run builds an
  in-memory registry of (shared + this tenant's imports). This is O(shared+imports) per run — bounded
  and acceptable for the expected catalogue sizes, revisited only if import counts grow large.
