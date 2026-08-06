# 0014. Audit emission is fail-closed for security-material actions

Date: 2026-08-06 · Status: accepted (supersedes the "emit never raises / fail-open" aspect of
[ADR 0006](0006-audit-trail-and-provenance.md), Decision 3 & 4)

## Context

ADR 0006 (issue #59) delivered the append-only, hash-chained, PII-free audit trail and an injected
`AuditEmitter`. It deliberately made emission **best-effort / fail-OPEN**: `emit()` "never raises",
so a rejected or un-persistable event was logged (class-name-only) and dropped, "so auditing can
never crash the audited action." That was the right default for a young subsystem, but it left two
gaps for a **compliance-first** platform (issue #99):

1. **Coverage gap.** Only `run.executed` and `finding.emitted` were emitted. The state-mutating
   `POST .../estate` (`put_estate`), `POST .../graph` (`put_graph`), and `POST .../snapshot`
   (`snapshot`) endpoints replace/freeze durable state but emitted **no** audit event at all — so a
   consequential mutation could leave no account.
2. **Durability gap.** Because emission was fail-open, even an *audited* action could succeed with
   **no durable audit record** if the audit store append failed (a hard audit-store outage). The
   trail was therefore not a guaranteed-complete or durable account of state mutations.

The human decision on #99 is **made and accepted**: for a compliance-first platform, a hard
audit-store outage must **block mutating writes** rather than let them proceed unrecorded. READS
are unaffected (they mutate nothing and emit nothing).

## Decision

**1. Close the coverage gap — audit the three state-mutating endpoints.** `put_estate`,
`put_graph`, and `snapshot` each now emit a PII-free audit event with a **bounded, DERIVED**
subject built by a single-source-of-truth helper, recorded as an **audit-BEFORE-write precondition**
(Decision 2):

- estate replaced → `"wl:<digest>#estate=<count>"` (node count only)
- graph replaced → `"wl:<digest>#graph=nodes=<n>,edges=<m>"` (counts only)
- snapshot created → `"wl:<digest>#snapshot"` (a bounded intent marker)

where `wl:<digest>` is `"wl:" + sha256(workload).hexdigest()` — the FULL 64-char hex, an opaque,
one-way, fixed-charset/length token derived from the workload id by `_workload_token`.

**Subjects are PII-free BY CONSTRUCTION.** The caller-controlled `workload` name reaches the API
only weakly constrained by the audit contract's `is_audit_safe` denylist, which still admits values
that *look like* PII (e.g. `John.Doe`, `MRN-123456`, `123-45-6789`). Rather than embed that raw name
in the durable subject (which would falsify any "PII-free" claim), the three new subjects embed the
**opaque digest** instead. Because sha256 is one-way and its hex output is a fixed 64-char subset of
`[0-9a-f]`, no PII (or unbounded free text) can appear in the subject regardless of the workload
name, while the trail stays correlatable via the stable digest. The FULL digest is retained (not a
truncated prefix) so the token is collision-resistant (>=128-bit): a caller controlling workload
names cannot birthday-collide two distinct names to the same token and thereby make their durable
audit subjects ambiguous. The subject also never carries
estate/graph content, a resource id, or any other free text — only counts and the digest.

*Snapshot subject is intent-only, by necessity.* The store-generated snapshot id
(`snap::<workload>::<seq>`) both embeds the raw workload name **and** is known only *after* the
write (a write-time autoincrement). To keep the record a true audit-BEFORE-write precondition **and**
PII-free by construction, the durable subject records the bounded intent (`wl:<digest>#snapshot`),
not the id. Over-recording (an intent whose subsequent write then fails) is the deliberately-safe
direction for a repudiation control. The opaque snapshot id is still returned to the caller in the
HTTP response body.

*Honest scope note (the pre-existing subjects).* The **pre-existing** `finding.emitted`
(`"<workload>#count=<n>"`) subject is **left unchanged** by this issue and still embeds the raw
workload id; the **pre-existing** `run.executed` subject carries the **module identifier** (not the
raw workload id, and not PII). Digesting `finding.emitted` would change long-standing validation
semantics and break its existing tests, and is out of #99's remit. So this ADR claims "PII-free by
construction" **only** for the three new state-mutation subjects (estate/graph/snapshot); the sole
residual raw-workload subject is `finding.emitted`. Tightening the **authoritative workload-ID
grammar itself** (in the
contract `src/shared/contracts.py`, which admits the PII-looking names above) is a separate follow-up
owned by the tenant-isolation work (**issue #65**) and is intentionally not attempted here.

*Contract note / `TODO(human)`.* The `AuditAction` enum (in the CONTRACT `src/shared/contracts.py`)
has **no** `estate.replaced` / `graph.replaced` / `snapshot.created` members, and modifying the
contract was **out of scope** for this issue (disjoint from two concurrent builds; contract changes
go via the Architect + an ADR). These three events therefore reuse **`AuditAction.run_executed`** —
the umbrella "consequential state mutation by the single writer" action (`commit_run` already
records estate+graph writes under `run.executed`) — disambiguated by the derived subject. Adding
dedicated action members is a small, clean follow-up contract change; they would be fail-closed
automatically by the same policy set below.

**2. Close the durability gap — fail-CLOSED, audit-BEFORE-write, for security-material actions.**
`AuditEmitter` carries an explicit, documented policy set
`FAIL_CLOSED_ACTIONS = {run.executed, finding.emitted}` (which, per Decision 1, also covers the
estate/graph/snapshot replacements, since they reuse `run.executed`). When the durable
`append_audit` raises for an action in that set, `emit()` re-raises it as **`AuditPersistenceError`**
so the audited mutation fails — the API returns **5xx**.

Crucially, the mutating endpoints call the emit as a **PRECONDITION, before the state write**
(`_emit_or_fail_closed` in `main.py`): the durable audit record is appended FIRST and the state
mutation (`put_estate` / `put_graph` / `snapshot` / `add_findings` / `commit_run`) runs **only if
the append succeeded**. So a hard audit-store outage propagates as 5xx *before any state changes*,
and there is **no committed-but-unaudited state** — audit is a genuine precondition for the
mutation. This is the direction the accepted #99 decision requires: a hard audit-store outage
**blocks** mutating writes. The residual (safe) direction is over-recording: a write that fails
*after* a successful audit append leaves an audit record with no corresponding state change — better
than the reverse for a repudiation control.

**3. A narrow, explicitly-documented fail-OPEN allowance.** Genuinely non-material events stay
best-effort (logged + swallowed on append failure): the `pack.verify` **failure** breadcrumb and
module toggles. The justification is specific, not a blanket exception: a lost breadcrumb there does
**not** correspond to an unrecorded *successful* mutation — the `pack.verify` failure already
rejects the pack fail-closed regardless of whether its breadcrumb persists, and it is emitted
mid-pack-load (`PacksEngine`) where raising would convert a safe rejection into a crash. Keeping the
allowance keyed on the **action** (not a per-call flag) means the unmodified `PacksEngine` emit
stays fail-open automatically, with no cross-module change.

**4. The failure is observable.** Any append failure — fail-open or fail-closed — increments the
PII-free counter `audit_emit_failures_total{action=<AuditAction>}` on the injected process
`MetricsRegistry`, so an audit-store outage is visible on `/api/metrics` and can drive
health/alerting. The emitter takes the metrics registry structurally (a small `MetricsCounter`
`Protocol`), so `shared.audit` keeps no dependency on `shared.observability`.

**5. Event-construction rejection is unchanged.** A PII/invalid event still fails `AuditEvent`
construction and is dropped (`emit()` returns `None`). Because the emit is now an audit-BEFORE-write
precondition, the mutating endpoints treat a `None` return as a fail-closed condition too
(`_emit_or_fail_closed` raises `500`), so an un-auditable mutation is never accepted and no state is
written. The three new subjects are additionally PII-free by construction (Decision 1), so they
cannot be the cause of such a rejection.

## Consequences

- **+** Every consequential state mutation the API performs (estate/graph/snapshot replace, findings
  upsert, run execution) is now audited, and its durable record is a **precondition for the
  mutation**: the audit append happens FIRST and the state write runs only if it succeeded, so a
  hard audit-store outage fails the mutating write closed (5xx) with **no committed-but-unaudited
  state**.
- **+** The three new state-mutation subjects are **PII-free by construction** (opaque
  `wl:<digest>` token), so a caller-supplied workload name containing PII can never reach a durable
  subject.
- **+** The policy is an **explicit, reviewable** set (`FAIL_CLOSED_ACTIONS`) with a documented
  allowance — no silent swallow, no per-call footgun.
- **+** Audit-store outages are observable (`audit_emit_failures_total`) rather than invisible.
- **−** **Audit-before-write, not two-phase.** The safe residual is *over-recording*: a state write
  that fails *after* a successful audit append leaves an audit record with no corresponding state
  change (the request still correctly reports failure). True atomicity would need a cross-store
  transaction the state layer does not provide; this is the deliberately-chosen safe direction for a
  repudiation control (over-record, never under-record).
- **−** READS are intentionally unaffected — this changes availability posture for **writes** only:
  when the audit store is down, mutating endpoints return 5xx by design.
- **−** Only the **three new** state-mutation subjects are PII-free-by-construction; the pre-existing
  `finding.emitted` subject still embeds the raw workload id (the `run.executed` subject carries the
  module identifier, not the workload), and hardening the authoritative workload-ID grammar in the
  contract is a follow-up owned by the tenant-isolation work (**issue #65**).
- **−** Dedicated `estate/graph/snapshot` `AuditAction` members remain a follow-up contract change
  (`TODO(human)`); until then those events share `run.executed`, disambiguated by subject.
