# 0008. Pack content store backend: Azure Blob, digest-addressed

Date: 2026-08-04 · Status: accepted

## Context

The pack **registry** (`src/packs_engine/registry.py`, `content/registry/index.json`) is a
metadata-only, content-addressed *index*: `registry.publish(pack)` records
`{id, version, type, digest, signature}`, where `digest = canonical_digest(pack)` (SHA-256 over
`packs_engine.canonical.canonical_bytes`). It deliberately does **not** store pack bytes.

Pack **import** today happens in the CLI (`src/cli/packs_studio.py cmd_export`): it verifies a
bundle's detached Ed25519 signature (fail-closed via `verify_pack` / `Ed25519Verifier`) and then
calls `registry.publish(...)`. The runtime **engine** (`src/packs_engine/engine.py`, rooted at
`$WP_CONTENT_ROOT`) loads pack CONTENT from the content-root **filesystem**, independently of the
registry. Consequently a freshly imported pack that was never shipped inside the content-root image
has **no bytes to load** and is unresolvable at runtime — `import → assign → run` cannot work
end-to-end for such a pack.

We need somewhere to persist the **verified imported pack bytes** and a runtime resolver that loads
an assigned pack **by digest** and re-verifies it before execution. The store must honour the
non-negotiable guardrails: **keyless** (Managed Identity, no secrets/connection strings),
**in-boundary** (no external endpoints), and **fail-closed** (missing/tampered ⇒ resolve nothing).

## Decision

**1. Backend: Azure Blob Storage, content-addressed by digest.** The runtime content store is
Azure Blob Storage; the blob name is derived from the pack's registry `digest`
(`<digest>.pack`). Rationale:

- **Content-addressed** — the digest is the sole address, so the store is naturally deduplicated and
  the bytes are self-verifying against the registry identity.
- **No per-property size cap** — packs can exceed Azure **Table Storage's 64 KB/property** limit;
  Blob has no such cap.
- **Cheapest at scale** and **keyless via Managed Identity** (`DefaultAzureCredential`).
- **Mirrors existing infrastructure** — it reuses the same blob usage and keyless pattern already
  established by `LocalStateStore` / `AzureStateStore` in `src/shared/state.py`.

This is the recommended, **reversible** choice (the backend sits behind a Protocol; swapping it
touches one factory).

**Alternatives considered and rejected:**

- **Azure Files** — higher cost and an SMB/file-share model we do not need for immutable,
  content-addressed blobs. Rejected on cost/fit.
- **Azure Table Storage** — a **64 KB/property** value cap makes it unsuitable for pack bytes, which
  can be larger. Rejected on the size cap.
- **Local disk** — retained as the **dev/CI** backend only (`LocalPackContentStore`), never the
  cloud runtime store.

**2. Abstraction mirrors the state store exactly** (`src/packs_engine/content_store.py`):

- `PackContentStore` — a `runtime_checkable` `Protocol` with a minimal, content-addressed surface:
  `put(digest, data)` (write; single-writer/import-only), `get(digest) -> bytes | None` (read),
  `has(digest) -> bool`.
- `LocalPackContentStore` — filesystem-backed, digest-addressed (`<dir>/<digest>.pack`), atomic
  `put` via a per-writer temp file + `os.replace`. Store dir via `WORKLOADS_PACK_STORE_DIR`
  (default under the OS temp dir, like `_default_state_dir()`). Deterministic, Azure-free, dev/CI.
- `AzurePackContentStore` — Azure Blob, keyless via `DefaultAzureCredential`, blob name = digest,
  with a `from_env` classmethod. **Every `azure.*` import is guarded inside a method (or
  `typing.TYPE_CHECKING`)**, so importing the module never requires azure packages and `mypy src`
  passes with **no** azure SDK installed — exactly like `AzureStateStore`.
- `build_pack_content_store()` — selects the backend from `WORKLOADS_PACK_STORE_BACKEND`
  (`local` (default) | `azure`). **Unknown backend ⇒ fail closed (raises)**, mirroring
  `build_state_store()`.

**3. Single writer on import.** The verified canonical bytes are persisted **only** on import, after
signature verification succeeds and `registry.publish` records the entry. The bytes stored are
exactly `canonical_bytes(pack)` — the same bytes the `digest` was computed over — so they are
byte-for-byte re-verifiable. Today import is CLI-only, so this is wired in `cmd_export`
(`src/cli/packs_studio.py`); when the API import path lands it becomes the single writer (the API
already owns all shared-state writes). The registry contract stays **unchanged** — it remains a pure
metadata index and never stores bytes.

**4. Fail-closed digest re-verification on load.** `PacksEngine` gains optional `registry` +
`content_store`. When both are wired, `load_all` additionally resolves imported packs from the store
BY the registry's verified `digest` (`_resolve_imported_packs`). For each registry entry NOT already
shipped on the content-root filesystem it loads the bytes by digest and re-verifies
`canonical_digest(loaded) == registry.digest` (constant-time compare) **before the pack is allowed
to execute**. It **fails closed** — resolving to nothing, never executing — when the digest is
absent from the store, the bytes are unparseable/non-canonicalizable, the recomputed digest does not
match, or the manifest is malformed / mistyped. Because the registry digest is recorded only after a
successful signature verification on import, bytes whose recomputed canonical digest matches that
digest are exactly the verified content, so no separate signature check is required on load (and the
stored canonical bytes deliberately exclude the volatile signature fields). The content-root
filesystem remains a valid source for shipped packs; the store is an **additional** digest-addressed
source for imported packs. This preserves the existing (#37) guarantee that assigned resolution is
digest-bound and fails closed, and does not weaken any existing signature-verification or
digest-binding behaviour.

**4a. Shipped packs win by pack ID; imports use their own id namespace.** The runtime resolver
treats every content-root (shipped) pack id as authoritative at **every** version: an imported store
pack whose `id` matches any shipped id is never resolved — regardless of version or digest. Platform
packs are upgraded through platform releases (the content-root), not the import/store path, so
imports are customer/third-party packs that must use their own pack ids/targets. This prevents a
validly-signed HIGHER-version import (e.g. `default-notify@1.0.1` vs shipped `@1.0.0`) from being
merged last-wins by a consumer (alerts `routes.update`) and overriding/suppressing shipped/critical
policy. **Inter-import precedence** (last-wins merge across two imported packs of the same id) and an
explicit **per-workload pack assignment/pinning** model (so only assigned imported refs resolve) are
deferred to a follow-up — they need a product decision on whether signed imports may ever override
shipped/critical policy. This issue only makes shipped-wins-by-id airtight and does not build an
assignment model.

**4b. Shipped ops policy is authoritative per key; imports may only add keys.** Shipped-wins-by-id
(§4a) stops an imported pack from claiming a shipped pack's *identity*, but a genuinely-new-id
imported ops pack (its own id, so it passes the §4a gate) could still define an **existing shipped
route key** (e.g. `routes: {critical: devnull}`) and, being merged last-wins by
`alerts.load_ops_routing` (`routes.update` + last-wins `default`/`runbook`), suppress shipped
critical paging. To close this without building an assignment model, every loaded `Pack` now carries
an explicit `imported: bool` provenance flag (`False` for content-root packs, `True` for
store-resolved packs; set in `PacksEngine.load_all` / `_resolve_imported_packs`). `load_ops_routing`
applies **imported packs first and shipped packs last** in its last-wins merge, keyed on
`pack.imported` rather than iteration order, so a shipped key always wins per key while an imported
pack may only **add** keys the shipped policy does not define. This is an explicit provenance guard,
not an ordering coincidence, and the engine documents the invariant on `load_all`. Consumer audit:
`alerts.load_ops_routing` is the only override-style (last-wins) merge over a shipped safety property
and is hardened here; all other pack consumers are **additive/aggregating** and order-independent
(quality_checks `load_rules` accumulates independent rules → findings; dependency_graph accumulates
edges; aiops `_match_steps` accumulates advisory remediation steps across all tables; discovery
`definitions_from_packs` accumulates workload definitions), so an import can add but never suppress a
shipped conclusion — no change needed there.

**4c. Shipped rule ids are authoritative over imported rule ids (finding-id collision).**
`quality_checks.evaluate_rule` builds each Finding id as `{rule_id}::{node_id}` — NOT namespaced by
pack — and `state._write_findings` upserts last-wins on `(workload, finding_id)`. So a genuinely-
new-*pack*-id imported rule pack (which passes the §4a shipped-wins-by-pack-id gate) that REUSES a
shipped *rule* id would, for the same node, produce the same finding id and overwrite the shipped
rule's finding — an imported PASS could thereby suppress a shipped FAIL in persisted state (read
downstream by alerts). `load_rules` now resolves in TWO passes by the same `pack.imported`
provenance flag: SHIPPED packs first (their rule ids become authoritative), IMPORTED packs second —
any imported rule whose id collides with a shipped rule id is skipped with a surfaced note (`imported
rule '<id>' shadows shipped rule id — skipped (shipped wins)`); imported rules with new/unique ids
still load and augment. The fix stays at the LOAD layer; `_write_findings` persistence semantics are
unchanged. Sibling-consumer audit (persisted-finding id-collision suppression): **aiops** finding ids
`detect::<metric>::<node>` are FAIL-only (emitted solely on breach — there is no PASS to overwrite a
FAIL with) and same-id collisions across packs are merged in-run by a highest-severity winner that
cites every contributing pack, so an imported detector can neither suppress nor downgrade a shipped
breach; **dependency_graph** ids `spof::<node_id>` derive from the ESTATE node id (not a pack-
controlled value), are FAIL-only, and are computed once per run over an additively-merged graph — no
per-id last-wins PASS-over-FAIL channel; **discovery** emits workload definitions/estate, not
persisted Findings, and accumulates additively. None exhibit the shipped-vs-imported finding-id
collision, so only `quality_checks` is hardened. **Deferred (per §4a):** precedence AMONG two
SHIPPED packs sharing a rule id, and AMONG two IMPORTED packs sharing a rule id, remains part of the
escalated per-workload assignment/pinning decision.

**4d. Module-qualified finding identity (cross-module id-collision fix).** §4c reserves shipped rule
ids only *within* `quality_checks`; it does not stop an imported `quality_checks` rule from minting a
finding id that collides with a DIFFERENT module's finding. A finding id is `{rule_id}::{node}` and
rule ids are pack- (hence import-) controlled, so an imported rule with id `spof` on node `N`
produces `spof::N` (module `quality_checks`) — the exact id `dependency_graph` uses for a
single-point-of-failure. Persistence keyed on `(workload, finding_id)` alone (local SQLite PRIMARY
KEY / upsert conflict target, and the Azure `_merge_findings` `by_id` dict) let an imported PASSING
`spof::N` overwrite the `dependency_graph` SPOF FAIL and hide a real outage risk. The fix makes
finding **identity** module-qualified everywhere the id is treated as a key, WITHOUT changing the id
value (so #78 opaquing and the API are unaffected): local `findings` PRIMARY KEY →
`(workload, module, finding_id)` with the upsert conflict target matched; Azure `_merge_findings`
keys by `(module, id)`; and `compute_drift` (the shared reassessments diff over ALL modules) keys
`newFailures`/`recovered`/`stillFailing` by `(module, id)` so a `quality_checks` `spof::N` PASS is
never mis-diffed as "recovering" a `dependency_graph` `spof::N` FAIL. New-wins still applies within a
single `(module, id)`. Reader audit: aiops `run_windowed_detectors` `by_id` fuses only aiops
detectors (all module `aiops`) so id-keying is in-module and safe; alerts reads `get_findings` and
routes each finding independently (labels payloads by id, no cross-module dedup), so once both rows
persist it routes both. This persistence-identity fix — not a fragile cross-module id reservation at
the load layer — is the complete fix; the §4c intra-`quality_checks` shipped-rule-id-wins guard is
retained. On upgrade, a legacy on-disk `state.db` (created with the old `(workload, finding_id)` PK)
is transparently rewritten to the 3-column PK by an idempotent, atomic migration at `LocalStateStore`
init (`_migrate_findings_pk`, backfilling `module` from the stored Finding JSON when NULL), so the new
`ON CONFLICT(workload, module, finding_id)` upsert never hits a missing-constraint `OperationalError`.

**5. Keyless + in-boundary.** No secrets, keys, or connection strings live in code, config, packs,
or tests. Azure auth is Managed Identity via `DefaultAzureCredential`; only Key Vault-backed env var
*names* (endpoint, container) live in code. No call reaches an external/public endpoint.

## Consequences

- **+** `import → assign → run` works end-to-end for packs that were never shipped in the
  content-root image: the verified bytes resolve from the store by digest and execute only after a
  fresh digest re-verification.
- **+** The store is keyless, in-boundary, content-addressed, and fails closed on every
  missing/tampered/mismatched path — a tampered store entry is never executed.
- **+** The abstraction mirrors the state store, so the same keyless/guarded-import/backend-selector
  patterns (and their CI guarantees, incl. `mypy src` with no azure SDK) carry over unchanged.
- **+** The registry stays a pure metadata index; the design is reversible behind the Protocol.
- **−** The CLI stores bytes locally (colocated with the dist registry under `dist/store`); the real
  single-writer import belongs to the API import path, which is still held — until then, populating
  the cloud (Azure) store end-to-end depends on that path landing.
- **−** The store is currently unbounded (no GC/retention of superseded pack bytes); retention is a
  future ops concern, as with the audit log.
