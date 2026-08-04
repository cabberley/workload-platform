# 0009. Audit-store tamper-resistance: blob-state immutability/versioning + destructive-perm review (Table audit perms unchanged)

Date: 2026-08-05 · Status: accepted

## Context

ADR [0006](0006-audit-trail-and-provenance.md) delivered an **append-only, hash-chained** audit
trail: a reader recomputing the chain against the anchored HEAD can *detect* storage-layer edits,
reordering, and truncation. That is tamper-**EVIDENCE**. Its documented gap (0006 §"What hash
chaining does and does NOT protect against", and the #61 threat-model / RBAC review) is that a
sufficiently privileged principal — a **Contributor-role** identity with data-plane write — can
still **delete or overwrite the store out-of-band** (including the HEAD anchor) and start a fresh,
internally-consistent chain. Evidence without **RESISTANCE** is incomplete.

Ground truth of the current implementation (verified, and at odds with the issue's blob-centric
wording, which conflates the two stores):

- The **audit log is Azure-TABLE-based**. `AzureStateStore.append_audit` (`src/shared/state.py`)
  writes a create-only event row + an ETag-guarded HEAD row in the SAME partition
  (`_AZ_AUDIT_PARTITION`) as ONE entity-group `submit_transaction`. Rows are create-only in normal
  operation, but a principal with Table data-plane delete/merge rights can delete/overwrite rows
  out-of-band. There is no storage-layer immutability.
- The **Blob store** (`_write_blob`, container `state`) holds the write-once, version-scoped
  estate/graph/findings/snapshot artifacts — NOT the audit log. It wrote with `overwrite=True` and
  the account had no versioning/immutability policy.
- Storage, containers/tables, the per-component user-assigned identities and their least-privilege
  role assignments (#79/#80) live in `infra/bicep/modules/core.bicep`; the CD gate
  `scripts/cleanup_verify_state_writers.py` enforces `STATE_WRITE_ROLE_IDS`.

This ADR is **decision-independent hardening**: it ships the storage-layer tamper-resistance
achievable WITHOUT a disruptive audit-backend migration, and records the deeper migration as a
scoped, deferred human decision.

## Decision

**1. Blob-store immutability, versioning, and soft delete (primary deliverable).**
`core.bicep` now hardens the state account's blob service and the `state` container:

- **Versioning** (`isVersioningEnabled: true`) — an overwrite creates a new immutable *version*;
  prior bytes are retained, so an in-place clobber is recoverable and non-destructive.
- **Change feed** (`changeFeed.enabled: true`) — an append-only, out-of-band log of every blob
  mutation, independent of the application.
- **Blob + container soft delete** (`deleteRetentionPolicy` / `containerDeleteRetentionPolicy`,
  `stateSoftDeleteRetentionDays`, default 7) — a deleted blob/container is recoverable for the
  window.
- **Time-based immutability (WORM)** on the `state` container
  (`immutabilityPeriodSinceCreationInDays = stateImmutabilityRetentionDays`, default 7) — while in
  effect a blob cannot be deleted or overwritten. Left **unlocked** (no `state: 'Locked'`) so a
  human can extend/lock it out-of-band per the customer's retention decision (locking is
  irreversible → a deliberate human step, not baked into IaC). `allowProtectedAppendWrites: true`
  keeps append-blob semantics available under the policy, honouring the append-only guardrail and
  forward-compatible with the migration hook (§4). The policy resource is **gated on a new
  `manageStateImmutabilityPolicy` param (default `true`)**, threaded from `main.bicep` → `core`.
  Azure **rejects any PUT (create/update) on a LOCKED** time-based immutability policy — you can only
  EXTEND retention via the dedicated action, never re-PUT (even with identical properties). Because
  `main.bicep` **always** deploys `core`, an unconditional resource would make the FIRST deployment
  after a human locks the policy fail on it (a HIGH operational bug — it silently breaks the release
  pipeline). **Operational sequence:** deploy (unlocked) → operator EXTENDs/LOCKs the policy
  out-of-band per the retention decision → operator sets `manageStateImmutabilityPolicy=false` on all
  SUBSEQUENT deployments so IaC stops managing the now-locked policy. In CD this is done by setting
  the **`MANAGE_STATE_IMMUTABILITY_POLICY` repository variable to `false`** (not just a manual local
  param): the release workflow (`.github/workflows/release.yml`) threads it into BOTH the what-if and
  deploy `az deployment group` commands as
  `manageStateImmutabilityPolicy="${{ vars.MANAGE_STATE_IMMUTABILITY_POLICY || 'true' }}"`, so when
  the variable is unset it falls back to `true` (today's behaviour) and when set to `false` the
  pipeline stops PUTting the locked policy. The resource is a leaf (no output or other resource
  references it), so the conditional cannot break any reference.

Retention windows are `param`s with sane defaults; everything stays **keyless** (no keys/SAS — access
is Managed Identity only) and **in-boundary** (container `publicAccess: 'None'`; no new region — the
child resources inherit the account's `resourceGroup().location`).

**2. SDK-level write-once on the blob path.** `AzureStateStore._write_blob` now uploads with
`overwrite=False` (conditional `If-None-Match: *` create) instead of `overwrite=True`. Every blob
this store writes is addressed by a UNIQUE, version-scoped name (per-attempt `uuid4().hex` commit
components; a table-claimed monotonic snapshot sequence), so no legitimate path ever re-writes an
existing name — the sole mutable commit point is the *manifest Table entity*, guarded by its own
ETag, NOT a blob. A name collision (a racing rewrite, or an attacker overwriting a committed
artifact in place) now **fails closed** with `ResourceExistsError` rather than silently clobbering.
The manifest/findings/snapshot read/write contracts are unchanged (the manifest is a Table entity;
this touches only blob writes).

**3. Table audit store destructive perms — why they are NOT restricted and it stays Table Data Contributor.**
Azure Table Storage has **no built-in append-only data role**, and its RBAC data actions
(`…/tableServices/tables/entities/{read,write,add,update,delete}/action`) **cannot be scoped to an
individual table by name** — a custom role can only grant/deny an action across ALL tables on the
account. The single-writer commit path legitimately needs entity update/merge on OTHER tables — the
manifest commit point (`workloads`, `update_entity` replace) and the snapshot pointer (`snapshots`,
`update_entity` merge). A role that denied `entities/delete`+`entities/write` to protect the audit
table would therefore ALSO break those non-audit writes. **A truly append-only Table role is not
expressible without breaking the writer.** 

**The blob-service controls in §1 do NOT protect the Table audit stream.** Blob versioning, change
feed, blob/container soft delete, and the container immutability (WORM) policy are **blob-service**
controls scoped to the blob `state` **container**: they protect the blob **state artifacts**
(estate/graph/findings/snapshot/manifest blobs) and provide **no storage-layer tamper-resistance to
Azure Table entities**. The audit stream is a **Table**, and the destructive Table role (Table Data
Contributor) is **unchanged**, so a principal holding it can still replace/delete audit event
entities and advance the HEAD out-of-band. The Table audit stream's tamper-resistance **today**
therefore comes **only** from (a) the application-level create-only + ETag-guarded `append_audit`
path (no rewrite path is exposed) and (c) the documented migration (§4) of the audit log to an
immutable append-blob container — which remains the **required, still-unresolved** path to genuine
per-store audit WORM **precisely because** the §1 blob-service/WORM posture does not cover Tables.
Because **no role id changes**, the CD gate `scripts/cleanup_verify_state_writers.py`
(`STATE_WRITE_ROLE_IDS`) is intentionally **unchanged** — this ADR does not weaken or bypass it.

**4. Layered posture + deferred migration decision.** The layers protect two DISTINCT stores.
*Blob state store:* `#81` blob state-artifact hardening (versioning/change-feed/soft-delete + WORM)
gives storage-layer resistance to the blob artifacts (estate/graph/findings/snapshot/manifest). *Table
audit stream (the #59 hash chain):* its integrity today is `#59` hash-chain read-time **evidence** +
the application-level create-only/ETag `append_audit` path **resistance** — and NOTHING more. `#81`
did **not** restrict destructive Table perms (§3 concluded a per-table append-only Table role is not
expressible, so the Table Data Contributor role is unchanged — nothing was restricted), and the §1
blob-service/WORM controls do **not** extend to the Table audit stream. The audit log stays
**Azure-Table for now** because it is co-located with the rest of the single-writer state layer, works
identically on both backends, and the entity-group transaction gives atomic event+HEAD advance — a
property an append-blob would have to re-derive. Consequently the Table audit stream has **no
storage-layer WORM today**, and the migration below is the **required path** to it — not a
nice-to-have.

`TODO(human)` — **required (deferred) path to genuine per-store audit WORM: migrate the audit log to
an immutable append-blob container.** Until this lands, the Table audit stream has NO storage-layer
tamper-resistance (a Table Data Contributor principal can still rewrite/delete audit entities
out-of-band); only the application-level create-only/ETag append path and read-time hash-chain
evidence apply.

- **For:** a dedicated append-blob (or immutable) container gives the audit log its OWN WORM
  boundary independent of the mutable manifest/snapshot Tables; `allowProtectedAppendWrites` makes
  append-only enforceable *at the storage layer*, so even a Contributor principal cannot delete/
  rewrite audit history within the retention window; it removes the "Table RBAC cannot target one
  table" limitation (§3).
- **Against / cost:** re-deriving the atomic event+HEAD advance and strict chain linearity currently
  provided by the single-partition entity-group transaction (append blobs have no multi-object
  transaction); a second storage surface + backend code path to maintain and test; retention/GC of
  an unbounded immutable log (also an open ops concern for the current store); and a data migration
  of any existing Table audit history.

Keeping this as a documented hook preserves #81 as decision-independent while leaving the deeper
choice — and its trade-offs — for a human to make in a dedicated follow-up.

## Consequences

- **+** Destructive **blob** operations (on the blob state artifacts) become recoverable
  (versioning/soft delete) and, within the WORM window, *prevented* (immutability) — the blob state
  store's tamper-**evidence** is now backed by tamper-**resistance**. (This does NOT extend to the
  Table audit stream — see below.)
- **+** The blob write path fails closed on any in-place overwrite (`overwrite=False`), catching a
  clobber at the SDK edge, not just at read time.
- **+** The WORM policy is IaC-managed but **safely re-deployable after an out-of-band lock**: the
  `manageStateImmutabilityPolicy` gate lets an operator stop IaC from re-PUTting the (now-locked)
  policy, so `core` — which `main.bicep` always deploys — no longer fails on it post-lock.
- **+** Everything stays keyless, in-boundary, and least-privilege; the CD state-writer gate is
  untouched (no role id churn).
- **−** The **Table audit stream** gains **no storage-layer tamper-resistance** from this work — the
  §1 blob-service/WORM controls cover blobs only, and Table Data Contributor is unchanged, so a
  holder can still rewrite/delete audit entities out-of-band. Its resistance is limited to the
  application-level create-only/ETag append path + read-time hash-chain evidence **until the
  append-blob migration (§4) lands** — the required path to genuine per-store audit WORM.
- **−** WORM retention is unlocked by default (reversible/safe), so full irreversibility requires a
  deliberate human lock; and the immutable/versioned store is unbounded (retention/GC is a future
  ops concern, as with the audit log itself).
