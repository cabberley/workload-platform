# 0013. Finding provenance is an enforced, fail-closed invariant

Date: 2026-08-06 · Status: accepted

## Context

Guardrail #8 (**Provenance**) requires that *every finding cites its evidence (resource id, metric,
pack + version)*. Issue #59 (ADR 0006) delivered the **evidence** half: a finding must cite at
least one attributable `SourceReference`, enforced at the persistence choke point and the
`run_module` emission boundary (`shared.provenance.enforce_finding_provenance`, fail closed).

The **pack + version** half was, however, *not* enforced. `Finding.packId` / `Finding.packVersion`
defaulted to `None`, and ADR 0006 explicitly left them optional because "graph-derived findings
legitimately have no pack". The result was an honesty gap:

- A **pack-derived** finding (from a Rule or Telemetry pack) could be emitted with `packId=None`
  and nothing would reject it — provenance silently missing.
- A **structural** finding (e.g. the dependency-graph single-point-of-failure) was pack-less *by
  design*, but the platform distinguished it from a broken pack finding only by the implicit signal
  `packId is None` — an accidental omission and a legitimate structural finding were
  indistinguishable.

Issue #83 (decision-independent M7 hardening; builds ON TOP of #59) closes that gap: make
pack/version provenance an **enforced, fail-closed contract invariant**, without papering over
missing provenance with placeholder pack ids.

## Decision

**1. An explicit provenance marker on the contract.** `Finding` (in `src/shared/contracts.py`)
gains two additive, typed fields — the only change to its shape (the `AgentResponse`/`Finding`
contracts are not otherwise forked):

- `provenance: ProvenanceKind` — an explicit `StrEnum` of `pack` | `structural`, **default
  `pack`**. This is the attribution marker; provenance is now a *declared* fact, never inferred
  from `packId is None`.
- `structuralKind: StructuralFindingKind | None` — an **allowlist** enum of the platform-computed,
  pack-less finding kinds (today: `spof`, the dependency & blast-radius single point of failure).
  Only an enumerated kind may be marked structural, so pack-less findings are an explicit,
  reviewable set — not an open escape hatch.

**2. A fail-closed Pydantic `model_validator` (construction-time).** A `Finding` is valid ONLY if:

- `provenance == pack`: BOTH `packId` and `packVersion` are present and **non-blank** (a
  present-but-whitespace value is not real provenance), AND `structuralKind is None`; **or**
- `provenance == structural`: `structuralKind` names an allowlisted `StructuralFindingKind`, AND it
  carries **no** `packId`/`packVersion` — both must be **exactly `None`**, not merely blank. A
  present-but-whitespace `packId`/`packVersion` is still pack identity and is rejected, so a
  structural finding can never smuggle a (blank) pack field past the gate.

Anything else — the common failure being the default `pack` with a missing/blank `packId` — raises
at construction. **The default (`pack`) does not hide missing provenance: it demands pack id +
version.** The dangerous default (silently treating a pack-less finding as valid "structural") is
deliberately *not* available; structural is opt-in and must name its kind.

**2b. The invariant holds after construction, and at persistence (defense in depth).**
`Finding.model_config` sets `validate_assignment=True`, so the `model_validator` re-runs on **every
attribute assignment** — mutating a provenance field into an invalid combination (e.g.
`finding.packId = None` on a pack finding) raises immediately rather than silently producing an
invalid, later-persisted finding. As belt-and-braces, the two durable-write boundaries in
`shared.state` (local `_write_findings` and the Azure `_commit`) call
`shared.provenance.revalidate_finding_provenance`, which re-validates each finding's round-tripped
`model_dump()` — so even a finding constructed via `model_construct` (which bypasses validation)
is rejected fail-closed before any row/blob is written, mirroring the #59 evidence gate at the same
choke points.

**2c. Structural provenance is bound to its authorized emitter module (issue #83, guardrail #8).**
A single source of truth `STRUCTURAL_FINDING_EMITTERS: dict[StructuralFindingKind, str]` maps each
structural kind to the one platform module authorized to compute it (today: `spof ->
"dependency_graph"`). After the structuralKind/exact-None checks, `_enforce_provenance` looks up the
authorized emitter for `self.structuralKind` and **rejects** if `self.module` is not that module —
so a caller cannot mint a packless "critical" finding under an unrelated module (e.g. a
`module="quality_checks"` finding marked `structural`/`spof`) to bypass the pack-citation
requirement. The lookup is **fail-closed on an unmapped kind**: a `StructuralFindingKind` with no
entry in the map is rejected outright, so adding a future kind without wiring its emitter mapping
fails closed rather than silently passing.

**Residual (honest scoping).** `Finding.module` is *self-declared* on this branch. Findings are
ingested via **two** paths — `POST /api/workloads/{workload}/findings` (`add_findings`, used by
`cli/state_client.py`) **and** `POST /api/workloads/{workload}/results` (`submit_results` →
`commit_run`, used by the compute-only ACA worker `cli/worker.py`) — and both funnel through the
same `Finding` model validator + persistence revalidation, so the emitter-module allowlist applies
to both. But neither path authenticates the *declarer*, so the allowlist is defense-in-depth against
an **honest** module mismatch, not a dishonest spoofer. Crucially, **#64 (Entra auth) + #79
(per-component identities) as currently designed are insufficient**: #79 provisions a **single
shared worker identity** across modules, so an authenticated worker identity cannot distinguish
`dependency_graph` from another module running under that same identity. FULL enforcement therefore
requires **per-module identities** (a distinct authenticated identity per emitting module) **or a
signed, module-bound submission capability** (a token/credential that cryptographically binds a
submission to the emitting module) — not merely Entra auth plus the shared worker identity. A
`TODO(human)` at both ingestion points (`add_findings` and `submit_results`) records this. No auth
mechanism is invented here.

**3. Emitters declare their provenance honestly.**

- *Pack-derived* — `quality_checks.evaluate_rule` (Rule Packs) and `aiops` telemetry detectors
  (`detect_metric_breach` threshold + `_build_finding` window/expression) thread the **real**
  `packId`/`packVersion` from the pack that produced the finding (stamped by `load_rules` /
  `load_telemetry_rules` / `compile_detectors` from the verified pack manifest — never a
  placeholder). `detect_metric_breach` now sets pack provenance at construction (threaded via
  `_breach_input`), so the merged detection is a valid pack finding without post-hoc mutation.
- *Structural* — `dependency_graph.spof_findings` sets `provenance=structural`,
  `structuralKind=spof`, and carries no pack id/version.

**4. Relationship to #59 (orthogonal, layered).** #59 = *evidence* completeness (cite ≥1
attributable `SourceReference`); #83 = *attribution kind* completeness (declare + prove
pack-vs-structural). They are independent: a pack-derived finding with valid `packId`/`packVersion`
can still fail the #59 evidence guard, and a structural finding still cites evidence. Both remain in
force; #83 does not replace or weaken the #59 persistence/emission guard.

## Consequences

- **+** Pack/version provenance is now guaranteed for every pack-derived finding, and pack-less
  findings are an explicit, enumerated, reviewable allowlist — the implicit `packId is None` signal
  is gone. Missing provenance fails closed at construction, before a finding can be emitted or
  persisted.
- **+** The change is additive to the `Finding` shape (two typed fields) and honest — no synthetic
  pack ids are minted to satisfy the check.
- **−** Introducing a new platform-computed finding kind now requires adding a
  `StructuralFindingKind` member **and** a `STRUCTURAL_FINDING_EMITTERS` mapping to its authorized
  emitter module (and updating this ADR) — an intentional, small friction that keeps the pack-less
  set curated and fail-closed (an unmapped kind is rejected).
- **−** The `pack` default means a `Finding(...)` built without provenance raises unless it supplies
  `packId`+`packVersion` or opts into `structural`; existing finding-emitting tests were updated to
  declare provenance honestly (pack fixtures carry synthetic pack id/version; dependency-graph
  fixtures are marked structural). The #59 evidence-guard tests now build a #83-valid,
  evidence-empty finding, which cleanly demonstrates the two guards are orthogonal.
