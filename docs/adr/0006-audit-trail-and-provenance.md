# 0006. Audit trail + provenance: append-only events through the state layer

Date: 2026-08-04 · Status: accepted

## Context

The platform performs consequential actions on a customer's estate — verifying and (soon)
importing/assigning signed packs, executing module runs, and (later) toggling modules. Guardrail
#8 (**Provenance**) also requires that *every finding cite its evidence*. We had neither a
tamper-evident record of *who did what with which pack version and to what result*, nor an enforced
guarantee that a finding without provenance can never be emitted.

Two forces shape the design:

- **In-boundary, keyless, PII-free, fail-closed** are non-negotiable (see
  `.github/copilot-instructions.md`). An audit record must therefore carry only ids + pack versions
  + action/result — never a name, email, log body, or Azure resource *path*.
- The record must persist through the **existing single-writer state layer** so it works unchanged
  on **both** backends (local sqlite, Azure Table/Blob) and respects the single-writer invariant.

Part of the pack lifecycle (import/assign) is **held behind #37** (pack admission). We wire the
paths that exist today and leave `TODO(human):` markers where a held path would emit, rather than
building the held subsystem.

## Decision

**1. An append-only, PII-free audit contract.** `AuditEvent` (in `src/shared/contracts.py`) carries
`id, actor, action (AuditAction), subject, packId?, packVersion?, result (AuditResult), recordedAt`,
plus the chain-linkage fields `prevHash?, entryHash?` (populated by the storage layer at append
time — see Decision 6). It is `frozen` (immutable once built) and `extra="forbid"`. **Every
string id field — `id`, `actor`, `subject`, `packId`, `packVersion` — is validated PII-free at
construction** via `is_audit_safe` (the `id` field included: it has a `default_factory` of
`uuid4().hex`, which is always audit-safe, AND is still run through the validator so a
caller-supplied id cannot smuggle an email / resource path / control char / oversized value).
`is_audit_safe` rejects emails (`@`), names/free-text/log bodies (whitespace/control chars), Azure
resource paths (`/subscriptions/…`, case-insensitively), the empty string, and over-long values. A
PII-bearing event therefore **cannot be constructed** in any field; the surface fails closed. The
`AuditAction` members are `pack.import`, `pack.verify`, `pack.assign`, `run.executed`,
`finding.emitted`, `module.enabled`, `module.disabled`.

**2. Append-only, hash-chained persistence via the state layer.** `StateStore` gains
`append_audit(event)` / `list_audit(limit=…)` / `audit_head()`, implemented on both backends and
hash-chained (Decision 6):
- *Local*: an `audit` table plus `BEFORE UPDATE`/`BEFORE DELETE` triggers that `RAISE(ABORT …)` — so
  append-only is enforced *at rest*, tamper-evident even against the writer itself. The chain HEAD
  lives in a small mutable `audit_head` row advanced in the SAME `BEGIN IMMEDIATE` transaction that
  inserts the event, so read-HEAD + row-insert + HEAD-advance are point-in-time atomic.
- *Azure*: one entity per event (create-only, never update/delete), `RowKey` = the zero-padded
  chain index for chain-order reads. The chain HEAD is a reserved entity (`RowKey = _head`) in the
  **same** audit partition, holding the latest `entryHash` + next `index`. Each append writes the
  event row AND the HEAD advance in a **single Azure Table entity-group transaction**
  (`submit_transaction`) — both are in one `PartitionKey`, so the two writes are atomic (either both
  land or neither does). The HEAD advance is ETag-conditional (`IfNotModified`), so a concurrent
  appender that lost the race retries with the fresh HEAD and the chain stays strictly linear. There
  is therefore **no orphan window** (the HEAD can never point at a missing event row) and **no
  fork**, and the pattern reuses the store's existing ETag optimistic-concurrency model — so **no
  existing state-atomicity/partitioning invariant is weakened**. The store exposes no rewrite path.

**3. An injected emitter.** `shared.audit.AuditEmitter` builds + persists events and is composed at
the API boundary like the store/packs/clients (`get_audit_emitter` dependency; the API also injects
a store-backed emitter into the packs engine — the API is the single writer). `emit()` **never
raises**: a rejected (PII) or un-persistable event is logged with a class-name-only message and
dropped, so auditing can never crash the audited action. `resolve_actor` reads ONLY the
object/principal-id header (`x-ms-client-principal-id`), never a `*-name` header, and falls back to
the `system` principal.

**4. Wired emission paths (today):**
- `run.executed` — `POST /api/modules/{name}/run` and `POST /api/workloads/{workload}/results`
  (worker hand-off), success/failure from `result.ok`, subject = module name, actor from the
  request. Emitted in a `finally` so failed runs are audited too.
- `finding.emitted` — recorded AFTER findings are successfully persisted on every finding-writing
  path (`/results`, `/findings`, and the `/run` commit). The subject is **PII-free**: the workload
  id + a COUNT of findings (`<workload>#count=N`) — never a resource id or free text. Provenance is
  enforced BEFORE the write (Decision 5), so reaching the emit means the write succeeded. This is
  **emit-after-write, best-effort/fail-closed — NOT a two-phase transaction**: the fail-closed
  emitter never crashes the request if the append fails, and we deliberately do not attempt
  cross-store atomicity the state layer does not provide. The guarantee is *provenance-before-write*
  and *no crash on emit failure*, not that the event and the finding land atomically together.
- `pack.verify` **failure** — `PacksEngine.load_all` records a fail-closed rejection of a
  tampered/invalid pack before re-raising. Success-path verify is intentionally *not* emitted here
  (it would fire on every pack on every run — unbounded noise); the discrete once-per-import verify
  belongs to the held #37 admission boundary (`TODO(human):`).
- **Held / absent** (`TODO(human):` with the exact site): `pack.import` + `pack.assign` (held #37,
  in `cli/wiring.py`); `module.enabled/disabled` (no runtime toggle exists, in
  `shared/module_base.py`).

**5. Provenance completeness guard — authoritative at the persistence choke point.**
`shared.provenance.enforce_finding_provenance` (pure) raises `ProvenanceError` on any finding with
empty `evidence`. It is enforced **inside the state layer's write path on BOTH backends, before any
write** — local `LocalStateStore._write_findings` (inside the caller's transaction, so the whole
write rolls back) and Azure `AzureStateStore._commit` (before the first blob/table write). This
makes the persistence layer the **authoritative gate**, so EVERY finding-emitting path (API
`/results`, `/findings`, `/run` commit, and any future writer) fails closed — a finding without
`sourceReferences` can never be persisted on either backend. The API maps `ProvenanceError` to a
clean `422` (never a `500`) and persists nothing. The module-emission guard in `run_module` is kept
as **defense in depth**. We require evidence but not `packVersion` (graph-derived findings
legitimately have no pack).

**6. Tamper-evidence via canonical hash chaining.** Append-only stops in-place rewrites, but does
not by itself make modification/replacement/reordering/truncation *detectable on read*. We deliver
tamper-evidence at the application layer (decision-independent; no storage/infra decision needed):
- Each persisted record carries `prevHash` and `entryHash`, where
  `entryHash = sha256(canonical_bytes(event_fields_excluding_hashes) || prevHash)`.
  `canonical_bytes` is a STABLE serialization (JSON with `sort_keys=True`, `separators=(",",":")`,
  JSON-mode so `recordedAt` is a fixed ISO-8601 string) — the same canonicalization approach already
  used for pack version identity (`packs_engine.canonical.canonical_bytes`) and graph revisions
  (`shared.blast_radius.graph_revision`), not a new one. `prevHash`/`entryHash` are excluded from the
  hash so the digest covers only the logical event.
- The genesis anchor (the `prevHash` of the first event) is a fixed, documented constant:
  `GENESIS_HASH = "0"*64`.
- An anchored chain HEAD (the latest `entryHash`) is advanced as part of the same append operation
  (local: same sqlite transaction; Azure: single-entity ETag-conditional write). `audit_head()`
  exposes it.
- `shared.audit.verify_audit_chain(events, head=…)` is **pure** over the read sequence: it recomputes
  the chain and returns the index of the first broken link (or `None` if intact). It **detects** a
  tampered field (recomputed `entryHash` mismatch), a reorder/insertion/deletion (`prevHash` no
  longer matches the running head), and — using the anchored `head` — a truncated tail (an otherwise
  valid but shortened chain whose terminal hash ≠ the HEAD returns `len(events)`).

**What hash chaining does and does NOT protect against.** It makes storage-layer *edits, reordering,
and truncation* **detectable on read** — a reader recomputing the chain against the anchored HEAD
will see the first broken link. It does **NOT** by itself *prevent* a sufficiently privileged
principal (e.g. a Contributor-role identity with write access to the store) from **deleting the
entire audit store**, including the HEAD anchor, and starting a fresh consistent chain — nor is it a
cryptographic signature (the hashes are keyless SHA-256, in keeping with the keyless guardrail, so
they prove *integrity/linkage*, not *authorship*). Preventing wholesale deletion requires
**storage-level immutability** (e.g. immutable/WORM blob policies, append-only table retention) or an
out-of-boundary anchor — tracked as the dedicated follow-up **issue #81** (audit-store
tamper-resistance: blob immutability/versioning + restricted destructive permissions), not in scope
here.

## Consequences

- **+** Every consequential action that exists today is recorded to a tamper-**evident**,
  append-only, PII-free log that works identically on both backends; no finding can be emitted
  without evidence, enforced authoritatively at the persistence choke point on both backends.
- **+** A reader can *detect* storage-layer edits, reordering, and truncation via
  `verify_audit_chain` against the anchored HEAD — the trail is genuinely tamper-evident, not merely
  append-only.
- **+** Auditing is best-effort in front of a durable append-only store: it never breaks the action,
  yet the append-only + hash-chain guarantees are enforced at rest.
- **−** The audit log is append-only and unbounded; retention/compaction is a future ops concern.
- **−** Hash chaining detects tampering on read but does not *prevent* wholesale deletion of the
  store; **storage-level immutability (WORM)** remains a documented follow-up (**issue #81**).
- **−** `finding.emitted` is emit-after-write (best-effort), not two-phase — a crash between the
  finding write and the emit can drop the audit event (never the finding); the chain HEAD's
  two-phase claim likewise makes a mid-append crash show as a detectable truncated tail.
- **−** Held pack lifecycle events (import/assign, success-path verify) and module toggling are
  `TODO(human):` until #37 / a toggle path lands — deliberately not built here.
