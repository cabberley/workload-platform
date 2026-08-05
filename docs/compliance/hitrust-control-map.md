# HITRUST CSF control mapping — Workloads Platform (codename *Aegis*)

Status: **draft, for GA alignment** · Framework: **HITRUST CSF** · Last reviewed: 2026-08-04 ·
Tracking issue: **#63**

This document maps the platform's **implemented, in-boundary technical controls** to the relevant
**HITRUST CSF** control domains, with a concrete **evidence reference** (file / module / issue) for
each. It is deliberately **honest**: every row is marked **Implemented**, **Partial**, or
**Planned**, and it does **not** claim controls the codebase does not yet enforce.

> **Scope of this deliverable (decided for issue #63).** We deliver the *control mapping*, the
> *no-PII-egress CI audit*, and the *data-residency assertion* **now**. **Formal HITRUST
> certification is explicitly deferred to GA** — this document is the engineering alignment that a
> future assessment builds on, not a certification or an attestation.

## How to read the status column

| Status | Meaning |
|--------|---------|
| **Implemented** | The control is enforced in code/infra today, with tests and/or a CI gate. |
| **Partial** | The mechanism exists and is enforced, but a documented hardening gap remains (tracked by an issue). |
| **Planned** | Not built yet; tracked by an issue and intentionally out of scope for now. |

## Platform guarantees these controls rest on

The five non-negotiable guardrails (`.github/copilot-instructions.md`, `ARCHITECTURE.md`) are the
backbone of the mapping below:

1. **In-boundary by construction** — every runtime component runs in the customer's own Azure
   subscription; only signed packs flow **in** and only opt-in, aggregated, **PII-free** findings
   may flow **out**.
2. **Keyless** — Managed Identity via `DefaultAzureCredential`; no secrets in code, config, or packs.
3. **Fail closed** — invalid signature / unknown resource / low confidence ⇒ surface, do not act.
4. **No auto-remediation** of customer infrastructure — advisory only; a human decides.
5. **Least privilege + provenance** — narrowest RBAC that works; every finding cites its evidence.

---

## Control-domain mapping

### 01 — Access Control

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| No shared/static credentials; unique identity per access | **Keyless** — all Azure access via user-assigned Managed Identity (`DefaultAzureCredential`); ACR admin user disabled; storage shared-key access disabled | **Implemented** | `infra/bicep/modules/core.bicep` (`adminUserEnabled: false`, `allowSharedKeyAccess: false`); `ARCHITECTURE.md` §First principles; guardrail #3 |
| Least-privilege authorization | **Read-plane RBAC** — the shared identity holds no control-plane write/Contributor; it is scoped to `Reader` + the storage/Key Vault **data** roles the platform needs | **Partial** | `infra/bicep/modules/core.bicep` (read-plane role assignments, issue #80). Today a **single** shared identity holds the *union* of the data roles (Queue/Blob/Table Data Contributor + Key Vault Secrets User) and the api-only-writer boundary is **not yet RBAC-enforced**; per-component managed identities with per-role scoping and an API-only-writer enforcement gate are being introduced (**#79**), at which point this control moves to **Implemented** |
| Per-component identity separation | Per-component (per-module) managed identities to further reduce the shared-identity permission union | **Planned** | tracked by **#79** (per-component identities); today a single shared user-assigned identity is used |
| Secrets never embedded | Runtime secrets resolved from **Key Vault by identity**; CI blocks committed secrets | **Implemented** | `infra/bicep/modules/core.bicep` (Key Vault, RBAC); `.github/workflows/security.yml` (gitleaks + guardrails secret scan) |

### 06 — Configuration Management

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| Only trusted content executes | **Signed, versioned packs** verified **before** execution; a present signature must be cryptographically proven or the build fails closed | **Partial** | `src/shared/contracts.py` (`PackSignature`); `scripts/validate_packs.py`; **Planned** hardening: mandatory signing once the KV trust root is provisioned (`WP_PACK_PUBLIC_KEY`, `WP_REQUIRE_PACK_SIGNATURES=1`) |
| Infrastructure defined as reviewed code | **Bicep IaC** deploys every component; each module is its own ACA app/Job with an honest scale profile | **Implemented** | `infra/bicep/**`; `ARCHITECTURE.md` §Independent scaling |
| Schema-validated configuration | Content packs are schema-validated in CI (fail closed on a malformed/absent manifest) | **Implemented** | `scripts/validate_packs.py`; `.github/workflows/pack-validate.yml` |

### 07 — Asset & Data Management / Data Residency

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| Customer data stays in the chosen region | **Data-residency assertion** — every deployable resource is co-located in the single resource-group region; the check **resolves indirection** (`var`/`param` defaults, object spreads) and **fails closed** on any value it cannot prove is `resourceGroup().location` or a permitted-region literal, including a **defaultless `location` param** unless *every* parent `module` call-site binding is validated | **Implemented** | `scripts/check_data_residency.py`; `tests/unit/test_check_data_residency.py`; `infra/bicep/**` (`location: resourceGroup().location`; child modules' defaultless `param location` bound at every `main.bicep` call site). **Residency boundary assumption:** `resourceGroup().location` is the single trusted dynamic source — a deploy-time-overridable location is treated as a violation |
| Data classification / handling | Domain data is processed and stored **only** in-boundary; no customer data, PHI/PII, or proprietary schemas in the repo (synthetic fixtures only) | **Implemented** | guardrails #1/#2; `.github/workflows/security.yml` (PHI/PII fixture scan) |

### 09 — Communications & Operations Management (transmission & egress protection)

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| No PHI/PII leaves the boundary | **No-PII-egress CI audit** — the audit imports the FastAPI app, enumerates the **real** response models from every route's `response_model` (and notification payloads), and **recursively** walks the full serialized schema graph (nested models, `list`/`dict`/`Optional`/`Union` members, computed fields, `RootModel`), checking each field's **effective emitted key** (alias / `serialization_alias`) against a PII denylist; CI fails closed if a PII-named or unclassified field is introduced | **Partial** | `scripts/audit_no_pii_egress.py`; `tests/unit/test_audit_no_pii_egress.py`; `src/api/app/main.py` (route `response_model`s); `src/modules/alerts/module.py` (`_notification_payload`). **Residual gap:** the platform still exposes **unbounded open mappings** on egress models — `ModuleRunResult.extra` (`dict[str, Any]`) plus `states`/`tags`/`labels` and several routes that return a raw `dict` — whose emitted keys cannot be statically bounded. The audit **flags every one fail-closed** and permits only an explicit, issue-referenced **tracked waiver** (printed loudly as `TRACKED WAIVER (#91)`); closing these open mappings to bounded schemas is tracked by **#91** ([security] bound/redact externally-returned free-form mappings & raw-dict endpoints), at which point this control moves to **Implemented**. The highest-risk residuals are `ResourceNode.tags` (populated via the estate API and returned by its GET endpoint) and `ModuleRunResult.extra` |
| Encrypted transport | Storage enforces `minimumTlsVersion: TLS1_2`; edge connectors use TLS-verified bounded transport | **Implemented** | `infra/bicep/modules/core.bicep`; `docs/adr/0004-connector-framework.md` |
| Egress-value hardening (opaque ids) | Free-text finding fields (`Finding.title`/`detail`), `ResourceNode.name`/`tags` **values**, and opaque-finding-id enforcement are **value-level** hardening a static field-name audit cannot see | **Partial** | tracked by **#78** (opaque finding ids); the field-name gate above is the regression guardrail; `_notification_payload` already excludes `nodeId`/`title`/`detail`/`evidence` |

### 10 — Audit Logging & Monitoring

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| Tamper-evident audit trail of consequential actions | **Append-only, hash-chained `AuditEvent`** trail (who/what/subject/pack version/result), NFKC-normalized and PII-free by construction; `verify_audit_chain` detects edits/reorder/truncation | **Implemented** | `src/shared/contracts.py` (`AuditEvent`, `is_audit_safe`); `src/shared/audit.py`; `docs/adr/0006-audit-trail-and-provenance.md` (issue #59) |
| Audit records carry no PII | Audit id-bearing fields are **NFKC-normalized**, reject Unicode `C*` (control/format) categories and whitespace, and reject Azure resource *paths* and email-shaped values (`@`, `/subscriptions/`, `/resourcegroups/`, `/providers/`); the persisted value is the canonical normalized form. Audit subjects are **PII-free by convention / derived-subject construction** (opaque ids, pack versions, results), never free user identity | **Partial** | `src/shared/contracts.py` (`_AUDIT_FORBIDDEN_SUBSTRINGS`, `AuditEvent` validators); `tests/unit/test_audit.py`. **Limitation:** the validator hardens *structure*, not *semantics* — it does **not** and cannot detect a value that merely *looks like* a plain human name (`is_audit_safe("Alice")` is `True`). PII-freedom therefore rests on the derived-subject convention above, not on name-content detection |
| Evidence/provenance for every finding | **Provenance guard** — a finding with empty `evidence` cannot be persisted on either backend (enforced at the persistence choke point) | **Implemented** | `src/shared/provenance.py`; `docs/adr/0006` §5 |
| Audit store immutability at rest (WORM) | Storage-level immutability / restricted destructive permissions | **Planned** | tracked by **#81** (audit-store tamper-resistance) |
| Self-observability (health / metrics) | Readiness/liveness + internal counters carry only low-cardinality names and numeric measures — never secrets/PII | **Implemented** | `src/shared/observability.py`; `docs/observability.md` (issue #60) |

### 10 — Secure Software Development Life Cycle

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| Static analysis & dependency/secret scanning | CodeQL, dependency review, gitleaks, Bandit, and platform guardrail checks on every PR | **Implemented** | `.github/workflows/security.yml` |
| Lint / type / test gates | `ruff` + `mypy` + `pytest` on every PR; every change ships a test | **Implemented** | `.github/workflows/ci.yml`; `pyproject.toml`; `AGENTS.md` (Definition of Done) |
| Change control via reviewed PRs | Small, single-issue PRs; contract changes require an ADR; no direct pushes to `main` | **Implemented** | `AGENTS.md`; `docs/adr/**` |

### 11 — Security Incident Management

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| Detect & route incidents | Continuous detection → blast-radius-weighted alert routing to the configured channel/runbook | **Implemented** | `src/modules/alerts/module.py`; `src/modules/aiops/**` |
| Advisory-only remediation | AIOps *proposes* RCA + remediation; a human always decides and applies (no auto-remediation of customer infra) | **Implemented** | guardrail #5; `docs/adr/0005-advisory-remediation-in-ops-packs.md` |

### 13 — Third-Party / Supply-Chain Assurance

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| Trusted third-party content | Microsoft ships **signed packs only**; the platform verifies signatures fail-closed before use | **Partial** | `scripts/validate_packs.py`; **Planned**: mandatory cryptographic verification once the KV trust root is provisioned |
| Multi-tenant / MSP isolation | Customer-owned by default; MSP via Azure Lighthouse with strict per-client data isolation | **Partial** | `ARCHITECTURE.md` §Trust boundary; runtime isolation enforcement is forward-looking |

### 13 — Privacy Practices / Data Protection

| Control objective | Platform control | Status | Evidence |
|---|---|---|---|
| Data minimization on egress | Only opt-in, aggregated, PII-free findings may cross the boundary; enforced by the no-PII-egress gate | **Partial** | `scripts/audit_no_pii_egress.py`; guardrail #1. Same residual as §09: unbounded open mappings — chiefly `ResourceNode.tags` and `ModuleRunResult.extra`, plus `states`/`labels`/raw-dict routes — are flagged fail-closed under a tracked **#91** waiver until they are narrowed to bounded schemas |
| No special-category (GDPR Art. 9) data | No PHI/PII fixtures; the no-PII-egress denylist explicitly covers special categories (health, ethnicity, religion, biometric) | **Implemented** | `scripts/audit_no_pii_egress.py` (`_PII_SUBSTRING_MARKERS`); `.github/workflows/security.yml` |

---

## Egress-boundary field inventory

The no-PII-egress gate (`scripts/audit_no_pii_egress.py`) treats these as the external-egress-facing
contracts and holds each to an allow-list of PII-free field names. Every field below is an **opaque
id, enum, count, metric, timestamp, resource id, or a nested audited contract** — never a
PII-typed field name.

| Contract | Boundary | Allow-listed fields | Why PII-safe |
|---|---|---|---|
| `alerts._notification_payload` | **True external** (webhook/Teams) | `findingId`, `severity`, `channel`, `runbook` | Explicit allowlist; excludes `nodeId`/`title`/`detail`/`evidence`. `findingId` value hardening tracked by #78 |
| `Finding` | API read model | `id`, `module`, `title`, `passed`, `severity`, `nodeId`, `blastRadius`, `evidence`, `packId`, `packVersion`, `detail`, `createdAt` | Ids/enums/counts/timestamps. `title`/`detail` are free-text **values** (value hardening tracked by #78) |
| `ResourceNode` | API read model | `id`, `name`, `type`, `workload`, `tier`, `role`, `tags` | Resource ids/classifiers. `tags` is an unbounded `dict[str, str]` mapping (emitted keys tracked by **#91**); `name`/`tags` **values** are a value-level hardening gap (#78) |
| `SourceReference` | API read model (evidence) | `kind`, `id`, `detail` | Provenance kind + resource/metric/pack id |
| `DependencyEdge` | API read model (graph) | `source`, `target`, `type`, `redundant`, `origin` | Node ids + enums/booleans |
| `WorkloadGraph` | API read model (graph) | `nodes`, `edges` | Nested audited contracts |
| `AgentResponse` | API read model | `agentName`, `taskType`, `inputSummary`, `findings`, `risks`, `recommendations`, `sourceReferences`, `confidence`, `nextActions`, `generatedAt` | Names/enums/metrics/timestamps; free-text lists are a value-level gap (#78) |
| `DriftReport` | API read model | `workload`, `newFailures`, `recovered`, `stillFailing`, `addedNodes`, `removedNodes` | Workload id + node-id deltas + nested findings |
| `GraphResponse` | API read model | `graphRevision` (+ inherited `WorkloadGraph`) | Topology hash |
| `ImpactResult` | API read model | `failedNode`, `states`, `blastRadius`, `down`, `degraded`, `graphRevision` | Node ids + enums + counts + topology hash |

**How the gate fails closed.** The audit **imports the FastAPI app** and derives its egress surface
from the **real routes** (`response_model` on every `APIRoute`, plus declared `responses[...].model`)
unioned with the notification payload(s) — so a newly added API response cannot silently drift past a
hard-coded list. For each response model it **recursively** walks the serialized schema graph to
arbitrary depth (nested Pydantic models, `list[Model]`, `dict[..., Model]`, `Optional`/`Union`
members, `RootModel` roots, and `model_computed_fields`), guarding against cycles with a visited set.
For **every** field it resolves the **effective emitted key** — honoring `alias`,
`serialization_alias`, `validation_alias`, and `AliasChoices` — and fails if that key matches a PII
marker (`email`, personal name, `ssn`, `patient*`, `phone`, `address`, a GDPR Art. 9 special
category, …). It **fails closed** on anything it cannot statically bound: an unbounded open mapping
(`dict[str, Any]`, `Mapping[...]`, `model_config extra="allow"`), a route with **no** `response_model`
that returns a raw `dict`/`Response`, dict-unpacking (`{**x}`) or computed dict keys in the
notification payload, or a failure to import/introspect the app — each is a **violation**, never a
silent pass.

**Tracked waivers (not silent passes).** The genuine pre-existing open mappings that live in
`src/**` (which this deliverable must not edit) — chiefly `ModuleRunResult.extra` and the
`states`/`tags`/`labels` maps, plus the raw-`dict` routes — are permitted **only** via an explicit
waiver keyed tightly on `Model.field` / `METHOD /path` **with a tracking issue** (`#91`). Waived
items are printed **loudly** as `TRACKED WAIVER (#91): …` so they stay visible; any unwaived open
mapping or unbounded route anywhere else is a violation. A mapping whose **key type is bounded**
(`Enum` / `Literal[...]`) needs **no** waiver — it is treated as bounded and its value type is still
recursed for PII; only free-form `str`/`Any` keys remain unbounded. This is why the §09 / §13 egress
controls are **Partial**, not Implemented.

**What it deliberately does NOT cover.** The audit inspects field **names / emitted keys**, not
runtime **values**. Free-text values in `Finding.title`/`detail`, `ResourceNode.name`, and
`AgentResponse` list fields could still carry customer-derived text; enforcing opaque ids/redaction
on those **values** is tracked by **#78**, while closing the open mappings above (`ResourceNode.tags`,
`ModuleRunResult.extra`, `states`/`labels`, raw-`dict` routes) to bounded schemas is tracked by **#91**.

---

## Documented fast-follows (not done here, tracked)

- **#78** — opaque finding ids + egress **value** redaction (the value-level complement to this
  name-level gate). A native `_notification_payload` `findingId` redaction hook is already flagged in
  `src/modules/alerts/module.py`.
- **#91** — bound/redact externally-returned free-form mappings & raw-`dict` endpoints
  (`ResourceNode.tags`, `ModuleRunResult.extra`, `ImpactResult.states`, `MetricSample.labels`,
  `DurationSample.labels`, and the raw-`dict` routes) so their emitted keys are statically bounded.
  Until then the no-PII-egress audit holds them as loud `TRACKED WAIVER (#91)` entries.
- **#79** — per-component managed identities (tighten the shared-identity permission union).
- **#81** — audit-store immutability at rest (WORM / restricted destructive permissions).
- **Mandatory pack signing** — provision the Key Vault trust root, then set `WP_PACK_PUBLIC_KEY` +
  `WP_REQUIRE_PACK_SIGNATURES=1` (see `scripts/validate_packs.py` / `pack-validate.yml`).
- **Formal HITRUST certification** — deferred to GA; this mapping is the engineering pre-work.

> A change that would ideally be a native bicep improvement (e.g. an explicit single-region policy
> assertion in `infra/bicep`) is intentionally **not** made here to avoid colliding with in-flight
> infra branches; `scripts/check_data_residency.py` enforces the same invariant read-only over the
> current templates.
