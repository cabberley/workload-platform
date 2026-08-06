# 0017. Tenant isolation model — customer-owned single-tenant default + opt-in MSP overlay, partition-key isolation, deny-by-default & fail-closed

Date: 2026-08-15 · Status: accepted

## Context

The platform ships **customer-owned single-tenant by default**: each customer's platform runs
**in-boundary**, inside the customer's own Azure subscription (guardrail #1), so normally exactly one
Entra tenant is served. [ADR 0011](0011-msp-delivery-via-azure-lighthouse.md) added an MSP-at-scale
delivery path via **Azure Lighthouse** — but that model keeps each customer deployment *separate and
customer-owned* (delegated, read-only ARM access; nothing centralised). Epic #17 (issue #65) asks for
the complementary **opt-in overlay**: a **single MSP-hosted instance serving several client tenants**,
where isolation can no longer rely on separate subscriptions and must instead be enforced **inside**
the one instance's state and read models.

Today the API core ([`src/api/app/main.py`](../../src/api/app/main.py)) resolves a validated,
non-PII `Principal` per request ([ADR 0016](0016-entra-auth-console-api-rbac.md)) but keys **all**
state by a bare `workload` string on BOTH storage backends ([`src/shared/state.py`](../../src/shared/state.py):
the local sqlite `LocalStateStore` and the Azure Table+Blob `AzureStateStore`). Nothing namespaces
state by tenant, so a single multi-tenant instance would let any caller read or overwrite any
`workload` regardless of which client it belongs to — a cross-tenant data-leak. `ARCHITECTURE.md`
already commits multi-tenant delivery to "strict per-client data isolation (row/partition + RBAC
scoping)"; this ADR makes that concrete.

The decision recorded on the issue (PM @cabberley): **customer-owned single-tenant is the DEFAULT;
MSP single-instance multi-tenancy via Azure Lighthouse is an OPT-IN overlay.** The isolation
mechanism must support BOTH — the default resolves to exactly one configured tenant, the overlay to
many. This is a **pre-GA / greenfield** change: there is no persisted customer state to preserve, so
the single-tenant DEFAULT continues to work for **new** deployments with no migration (see
"Backward-safety" below for the one exception — a pilot that already holds bare-key state).

## Decision

**Resolve exactly one tenant per request at the API boundary (fail closed), and namespace every
state write and filter every read/query by a pure, storage-safe TENANT PARTITION KEY threaded
through BOTH storage backends — deny-by-default, so a request without a resolved tenant, or one
targeting another tenant's partition, gets nothing (never cross-tenant data).**

### 1. Tenancy model — one contract, two modes — `src/shared/contracts.py`

Two delivery modes are modelled as a closed [`TenancyMode`](../../src/shared/contracts.py) enum and
each request resolves to exactly one [`TenantContext`](../../src/shared/contracts.py):

- **`single` (DEFAULT)** — a customer-owned single-tenant instance: exactly one configured tenant id,
  in the customer's own subscription (guardrail #1). The keyless local/dev/CI path (no token) is
  served *as* that one configured tenant.
- **`multi` (opt-in MSP overlay)** — one instance serving several client tenants via Azure Lighthouse
  ([ADR 0011](0011-msp-delivery-via-azure-lighthouse.md)); the caller's tenant is taken from its
  VALIDATED token per request and MUST be on a configured allowlist.

`TenantContext` is a Pydantic model, **frozen** + **`extra="forbid"`** (it cannot be widened
downstream), carrying a non-PII `tenant_id` (an Entra tenant GUID or verified domain — never a
name/email) and its resolving `mode`. A field validator plus the pure
[`is_tenant_id_safe`](../../src/shared/contracts.py) predicate constrain the id to a bounded,
storage-safe charset so it can never smuggle a quote, path separator, or OData operator into a
partition/row key (defense in depth beneath the hex-encoding the state layer already applies). **We
did NOT fork `AgentResponse`** or any existing contract; the tenant types are additive.

### 2. Pure partition-key logic (Azure-free) — `src/api/app/tenancy.py`

The tenant→key derivation is a set of **pure, deterministic, unit-tested** functions (pure logic ⟂
I/O — no Azure, no storage, no clock):

- [`tenant_partition_key(tenant_id, workload)`](../../src/api/app/tenancy.py) →
  `f"{hex(tenant_id)}.{workload}"`. The tenant id is **hex-encoded** to a fixed `[0-9a-f]` charset
  that can never contain the `.` delimiter, so two tenants sharing a workload NAME map to **disjoint**
  physical keys (the isolation invariant), and the mapping is **reversible**
  ([`split_partition_key`](../../src/api/app/tenancy.py) splits on the FIRST `.`) even when the
  workload name itself contains dots.
- [`workload_of(partition_key, tenant_id)`](../../src/api/app/tenancy.py) is the **deny-by-default
  filter** for read models: a key belonging to ANOTHER tenant yields `None` and is dropped, so a
  cross-tenant key can never surface as one of this tenant's workloads.

Because the id is a bounded, storage-safe token AND hex-encoded, the tenant becomes part of the
physical key on BOTH backends: the sqlite `workload` column, and the Azure `PartitionKey`/`RowKey` +
blob path (via the state layer's existing `encode_storage_key`). Because this is a **pre-GA /
greenfield** change with **no persisted customer state to preserve**, **no sqlite migration and no
Azure key-format change** are needed for a new deployment. (The one exception — a pilot that already
holds bare-key state written by a prior release — is addressed under "Backward-safety" below.)

### 3. Fail-closed tenant resolution — `src/api/app/tenancy.py`

[`build_tenancy_config`](../../src/api/app/tenancy.py) reads the tenancy config **keylessly** from
env (only variable *names* live in code; every value is a non-secret directory identifier):

| `WP_TENANCY_MODE` | Configured tenant(s) | Result |
| --- | --- | --- |
| unset / `single` (default) | `WP_TENANT_ID` (else `WP_AUTH_TENANT_ID`, else `default`) | **single** — one configured tenant; missing config ⇒ implicit `default` (the DEFAULT works out of the box) |
| `multi` | `WP_ALLOWED_TENANTS` (comma-separated) non-empty | **multi** — the allowlist of client tenants this instance may serve |
| `multi` | `WP_ALLOWED_TENANTS` empty/blank | **fail closed** (`multi_mode_requires_allowlist`) — an overlay with no allowlist would admit anyone |
| unknown value | — | **fail closed** (`invalid_tenancy_mode`) — never silently multi-tenant |

[`resolve_tenant`](../../src/api/app/tenancy.py) then resolves the ONE tenant a request may act
within from the VALIDATED token's `tid`:

- **`single`** — resolves to the configured tenant. A present `tid` MUST equal it (a token minted for
  a different directory is denied — `tenant_mismatch`); an absent `tid` (no-auth local/dev path) is
  served as the single configured tenant.
- **`multi`** — `tid` is **REQUIRED** (an absent/ambiguous tenant is denied, never guessed —
  `tenant_required`) and MUST be on the allowlist (`tenant_not_allowed` otherwise).

Every ambiguity raises `TenantResolutionError` carrying a **short reason code only** (never the
token, claims, or tenant id — PII-free by construction), which the API maps to a fail-closed **403**.

### 4. Tenant-scoped identity — `src/shared/auth/`

`Principal` ([`principal.py`](../../src/shared/auth/principal.py)) gained an additive, optional
non-PII `tenant_id` field; the validator ([`validator.py`](../../src/shared/auth/validator.py))
extracts the Entra **`tid`** claim from the *validated* token (absent/blank ⇒ `None`, never
fabricated). Tenant identity therefore derives from the **cryptographically validated** token, never
a spoofable header — consistent with the audit-actor discipline of
[ADR 0016](0016-entra-auth-console-api-rbac.md).

### 5. Tenant-scoped state + read models on BOTH backends — `src/api/app/tenant_state.py`

A [`TenantScopedState`](../../src/api/app/tenant_state.py) **facade** implements the full
[`StateStore`](../../src/shared/state.py) Protocol and wraps the process-wide store + the resolved
`TenantContext`. It maps each logical `workload` → its tenant partition key on every read and write,
and `list_workloads()` returns ONLY the current tenant's workloads (other tenants' composite keys are
filtered out and never surface). Isolation is **deny-by-default**: the tenant is bound at
construction and there is *no code path* that addresses another tenant's partition, so an endpoint
using the scoped store can only ever touch its own tenant's state and read models — on EITHER backend.

The API wires this at the boundary ([`main.py`](../../src/api/app/main.py)): `get_request_principal`
validates the token once per request (shared by the role gate AND tenant resolution);
`get_tenant_context` resolves the one `TenantContext` (fail-closed 403 with a fixed, PII-free body);
`get_scoped_store` hands every workload endpoint (all mutating POSTs and all read GETs) a
`TenantScopedState`. The global audit emitter, readiness/`_store_probe`, and health/metrics
endpoints deliberately stay on the raw store (see "Scope").

### Why a facade, not new Protocol parameters

Adding a `tenant` parameter to every `StateStore`/`ReadableState` method would ripple into
`src/modules/**` (the capability modules consume the read-only surface) — modules this change is
explicitly forbidden to touch, and whose isolation the architecture protects. The facade threads the
tenant into the existing `workload` argument as a composite physical key, keeping the Protocol
signatures — and thus module isolation — **unchanged** while still namespacing BOTH backends.

## Known limitation — multi-tenant overlay worker path (fail-closed, tracked follow-up #122)

**The overlay's isolation guarantee is scoped to the API surface.** Every request that reaches the
FastAPI core resolves its tenant from a validated token `tid` and is confined to that tenant's
partition (deny-by-default, fail-closed). But the **worker** is a separate process: it runs as the
shared platform managed identity (`identityWorker`) and mints its API bearer from that identity, so
its token's `tid` is the **deployment/host** tenant, **not** the client tenant whose workload it
processed. Consequently:

- In the **single-tenant DEFAULT** (the worker identity lives in the customer's own tenant) this is
  correct and leak-free — the host tenant *is* the one and only tenant.
- In the **`multi` overlay**, worker-**submitted** state would be attributed to the **host** tenant,
  not the client — worker-produced state is **not yet correctly tenant-attributed**. API-surface
  reads/writes remain tenant-isolated and fail-closed; the gap is specifically the worker submission
  path, which does not yet propagate per-customer tenant context.

**This is fail-closed by construction.** In `multi` mode a request whose validated claim is absent
is denied (`tenant_required` → 403) and one whose claim is not on `WP_ALLOWED_TENANTS` is denied
(`tenant_not_allowed` → 403). Because the host/worker tenant is **not** on the client allowlist by
default, a worker (or any host-tenant token) **cannot silently write into a client tenant's
partition** — it is rejected. A cross-tenant exposure could only arise if an operator **deliberately
allowlists the host tenant**, which this ADR explicitly forbids for production overlay use.

**Operators MUST NOT enable `multi` mode for production worker-produced state until the
worker-context follow-up (#122 — "Worker per-tenant context propagation for the MSP multi-tenant
overlay") lands.** The full fix — per-customer worker/job tenant context propagation — needs
`src/cli/**` and `infra/**` and is **out of scope for #65**; it is tracked as **#122** (relates to /
depends on #65). Until then the `multi` overlay is safe for **API-surface** tenant isolation and
fail-closed rejection, but is **not** a production-ready path for worker-submitted state.

## Backward-safety (pre-GA / greenfield — with one fail-closed migration caveat)

This change namespaces every physical key by tenant, so a bare (un-prefixed) `workload` key written
by a **prior release** becomes invisible after upgrade (composite-key reads no longer address it, and
`list_workloads()` drops keys that lack the current tenant's prefix). The honest posture:

- **New deployments (the expected case): no migration.** This is a pre-GA / greenfield change with
  no persisted customer state to preserve; the single-tenant DEFAULT works out of the box.
- **A pilot / in-flight deployment that already holds bare-key state:** a **one-time,
  single-mode-only, fail-closed migration** (re-key each bare `workload` into the ONE configured
  tenant's namespace) is required **before** upgrade. It is `single`-mode only by construction — a
  `multi` overlay must **never** adopt unscoped legacy keys (that would be exactly the cross-tenant
  read this ADR forbids). This migration is **not** implemented here (it needs the storage edge,
  `src/shared/state.py`, which is out of #65's scope) and is a **`TODO(human)` / tracked follow-up**.

We deliberately did **not** add an in-process legacy read-through adoption to `TenantScopedState`: a
safe version would have to be provably impossible in `multi` mode, and keeping the read path
uniformly tenant-scoped (no bare-key branch anywhere) is the stronger, less error-prone guarantee.

- **In scope, wired & tested:** the tenancy contracts (`TenancyMode`, `TenantContext`,
  `is_tenant_id_safe`); the pure partition-key logic and its reversible round-trip; fail-closed
  `build_tenancy_config` + `resolve_tenant` (single mismatch, multi required/not-allowed, invalid
  mode/allowlist); `Principal.tenant_id` + `tid` extraction; the `TenantScopedState` facade over the
  real `LocalStateStore`; and the API wiring on every workload endpoint. Unit tests prove the
  key/partition logic and the facade's cross-tenant disjointness Azure-free; API tests prove tenant A
  cannot read/write tenant B's state or read models, that a missing tenant fails closed
  (`tenant_required` → 403) and a non-allowlisted tenant fails closed (`tenant_not_allowed` → 403),
  and cover BOTH the single-tenant default and a 2-tenant overlay. **The overlay guarantee proven
  here is the API surface** (see "Known limitation — multi-tenant overlay worker path" for the
  worker submission gap).
- **`TODO(human)` — deploy-time / out of band / tracked follow-ups:**
  - **Multi-tenant overlay worker context (tracked follow-up #122).** Workers share the platform
    identity, so worker-submitted state is not yet per-customer tenant-attributed under the `multi`
    overlay (see "Known limitation" above). The fix needs `src/cli/**` + `infra/**` and is **out of
    scope for #65**; it is tracked as **#122** ("Worker per-tenant context propagation for the MSP
    multi-tenant overlay", depends on / relates to #65) and **must land before `multi` mode is
    production-safe for worker-produced state**. Until it lands, `multi` mode is fail-closed for the
    API surface but **must not** be enabled for production worker-produced state.
  - **`multi` overlay is not deployable via supported IaC yet (tracked follow-up #123).** Threading
    the (non-secret) tenancy env — `WP_TENANCY_MODE=multi` and
    `WP_ALLOWED_TENANTS=<client-tenant-guids>` — into the API/job container templates lives under
    `infra/**`, which this change does not touch. Until that infra env-threading follow-up —
    **#123** ("Thread tenancy mode + allowlist through Bicep", depends on / relates to #65) — lands,
    the `multi` overlay **cannot be turned on through supported infrastructure-as-code**.
    Single-tenant deployments need set nothing — the default resolves to the configured auth tenant,
    or `default`.
  - **Legacy bare-key migration (only if a pilot holds prior-release state).** A one-time,
    `single`-mode-only, fail-closed re-key into the configured tenant's namespace is required before
    upgrading any deployment that already holds un-prefixed `workload` keys (see "Backward-safety").
    It needs the storage edge (`src/shared/state.py`), out of #65's scope.
  - **Audit trail stays instance-wide.** The append-only, tamper-evident hash-chain audit
    ([ADR 0009](0009-audit-store-tamper-resistance.md) / [0014](0014-fail-closed-audit-emission.md))
    is instance infrastructure and is delegated by the facade **unchanged**; per-tenant audit
    partitioning is deliberately out of scope for #65 and would need its own ADR (the hash-chain head
    is a single instance-wide invariant).
  - In a `multi` overlay, `Workloads.*` app-role **assignments** ([ADR 0016](0016-entra-auth-console-api-rbac.md))
    must be granted per client tenant — the same Microsoft Graph deploy step, out of band.

## Consequences

- **+** Deny-by-default, fail-closed cross-tenant isolation: every write is namespaced and every read
  filtered by a tenant partition key on BOTH backends; a missing/ambiguous/mismatched tenant is a 403,
  never cross-tenant data.
- **+** Pre-GA / greenfield: the single-tenant DEFAULT works with **zero** config (resolves to the
  configured auth tenant or `default`); a new deployment needs no sqlite migration and no Azure
  key-format change. A pilot that already holds bare-key state needs a one-time, single-mode-only
  fail-closed migration first (see "Backward-safety"; tracked `TODO(human)`).
- **+** Pure logic ⟂ I/O: the isolation decision is pure, deterministic, and unit-tested Azure-free;
  storage stays behind the unchanged thin backends. Keyless and PII-free throughout (only non-secret
  directory identifiers; failures carry reason codes only).
- **+** Module isolation preserved: the `StateStore`/`ReadableState` Protocol signatures are
  unchanged, so `src/modules/**` is untouched.
- **−** The tenant hex prefix appears inside the physical key (and the opaque `snapshot()` id); only
  the owning tenant ever observes its own key/snapshot, so this is not a cross-tenant leak, but it is
  a mild format coupling left as-is to avoid brittleness.
- **−** Audit remains instance-wide (see `TODO(human)`); in an MSP overlay the audit log is a
  cross-tenant operational record for the instance operator, not a per-client trail — acceptable for
  #65, revisited if per-tenant audit is required.
- **−** The `multi` overlay is **API-surface-only** in this change: worker-submitted state is not yet
  per-customer tenant-attributed (workers share the platform identity — tracked as **#122**), and the
  overlay is not deployable via supported IaC until the infra env-threading follow-up (**#123**)
  lands. It is fail-closed (non-allowlisted/host and unauth tokens get 403) but **must not** be
  enabled for production worker-produced state until #122 ships.
