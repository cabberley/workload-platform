# 0011. MSP-at-scale delivery via Azure Lighthouse over customer-owned deployments

Date: 2026-08-05 · Status: accepted

## Context

The platform ships **customer-owned** by default: every module runs **in-boundary**, inside the
customer's own Azure subscription (guardrail #1). Epic #17 (M4) also requires a way for a Managed
Service Provider (MSP) to operate **many** such customer deployments **at scale** without weakening
that boundary.

Two models were on the table:

1. **Single-instance multi-tenant** — one MSP-hosted platform instance serving many customers. This
   **breaks the in-boundary guarantee**: customer estate reads, telemetry, and findings would have
   to cross into an MSP-owned tenant, creating a shared blast radius and a data-egress path for
   PHI/PII-adjacent metadata. Rejected.
2. **Azure Lighthouse delegated resource management** over deployments that **remain
   customer-owned** — the MSP's managing tenant is granted **scoped, read-only ARM access** into
   each customer subscription; nothing is centralised.

The accepted product decision (DECISION ACCEPTED, @cabberley) is model **2**.

## Decision

**Deliver the MSP-at-scale path as Azure Lighthouse delegated resource management, with
least-privilege, read-only delegated roles, over customer-owned deployments.**

- **IaC** lives in [`infra/bicep/lighthouse/`](../../infra/bicep/lighthouse/):
  - `subscription.bicep` (subscription scope) and `resource-group.bicep` (single-RG scope, the
    narrowest) create `Microsoft.ManagedServices/registrationDefinitions` +
    `registrationAssignments`.
  - `managedByTenantId`, offer name/description, and the MSP **principal identity**
    (`principalId` + `principalIdDisplayName`) are **parameters**. The `authorizations` array is
    **not** a parameter — it is built **inside** the templates from a fixed, hardcoded read-only
    allowlist and mapped onto the supplied principal (fail-closed). PIM-eligible
    (`eligibleAuthorizations`) access is **not** emitted — it needs policy sign-off (`TODO(human):`).
    **No** secrets and **no** customer identifiers are hardcoded; example params use
    **clearly-fake placeholder GUIDs**.
- **Least privilege, fail-closed (guardrail #7).** The delegation grants exactly **one** built-in,
  **read-only** role, **Reader** (`acdd72a7-3385-48ef-bd42-f606fba81ae7`), for control-plane estate
  discovery and `*/read`. Because roles come from an internal allowlist rather than a deploy-time
  parameter, no privileged role can be injected. **Monitoring Reader is deliberately NOT delegated:**
  it would broaden the grant with further data-plane monitoring actions
  (`Microsoft.OperationalInsights/workspaces/search/action`, `Microsoft.Support/*`) on top of
  `*/read`; keeping to Reader preserves least privilege at "Reader only". The *Managed Services
  Registration assignment Delete Role* (`91c1777a-f3dc-4fae-b103-61d183457e46`, MSP self-service
  off-boarding) is **not** granted by default — the customer can always revoke unilaterally.
  **Owner / Contributor / User Access Administrator are never granted.** Anything broader must be a
  `TODO(human):`, not a silent over-grant.
- **Finding1 — Reader's `*/read` includes telemetry (residual, Option B ACCEPTED).** Security review
  flagged that the built-in Reader role's `*/read` is not telemetry-free: it permits reading metric
  values and Log Analytics query **results** (e.g.
  `Microsoft.OperationalInsights/workspaces/query/read`), so a delegated MSP principal **can** read
  customer telemetry — a residual in-boundary concern (#1). Three options were considered:
  - **A — author a custom "no-telemetry" read role** that strips the telemetry/query read actions.
  - **B — accept the built-in Reader and compensate with auditing.**
  - **C — grant no read role at all.**

  **Decision: Option B is accepted** (product owner, @cabberley). We keep the single built-in Reader
  role and **honestly acknowledge** the telemetry-read residual rather than claiming false isolation;
  it is compensated by **auditing** (below), not by role scoping. **A is rejected but deferred** as a
  future hardening option — a custom role is a larger authoring/maintenance surface and can be
  revisited if the residual proves material. **C is rejected** — with no read role the MSP cannot do
  discovery or observability at all, defeating the purpose of the delegation.
- **Compensating control — targeted auditing (guardrail #8).** The audit surface must match how Azure
  actually logs, because **reads are not uniformly audited**: (1) the **Azure Activity Log records
  administrative CHANGES only, not reads**, so it does NOT capture the MSP's `*/read`, metric reads,
  or LA queries — its value here is to catch any **write/administrative** action by the managing
  tenant (which must never occur under Reader); (2) **Log Analytics queries are audited via the
  workspace `LAQueryLogs` diagnostic-setting audit category** — this is the real mitigation for the
  LA-query residual; (3) **metric-value reads (`Microsoft.Insights/metrics/read`) are NOT
  individually auditable** in Azure and are disclosed as an accepted, **unmonitored** residual
  (coarse mitigations only: narrow/remove the delegation, or adopt the deferred Option A custom
  no-telemetry role). All are **advisory and customer-owned** (guardrail #5, no auto-remediation);
  the audit data stays **in-boundary** in the customer's own workspace. See the onboarding doc.
- **Keyless (guardrail #3).** Delegation is pure Entra identity projection — no key, secret, SAS, or
  connection string anywhere. MSP operators authenticate from their own tenant.
- **Boundary preserved (guardrail #1).** Lighthouse itself copies/exports **no** data — the
  delegation is control-plane only, so no workload data, PHI/PII, or log bodies are copied, mirrored,
  replicated, or exported out of the customer tenant (**no bulk egress**), and Reader grants no
  access to patient data, raw log bodies, or secrets. Reader's `*/read` *does* let the MSP
  read workload **telemetry** (metric values + Log Analytics query results) from within the tenant
  (see Finding1); that residual is accepted under Option B and audited (LA queries via
  `LAQueryLogs`), not silently denied — so this is "no bulk data export", not "the MSP reads
  nothing".
- **Auditable (guardrail #8).** Administrative CHANGES by the MSP land in the customer's Azure
  Activity Log (reads do not — see the compensating-control bullet); Log Analytics queries are
  auditable via `LAQueryLogs`; the customer can inventory, audit, and **unilaterally revoke** the
  delegation at any time.
- **Docs**: [`docs/delivery/lighthouse-onboarding.md`](../delivery/lighthouse-onboarding.md) covers
  deploy / audit / revoke and the per-role rationale.
- **Validation**: templates compile with `az bicep build`; `scripts/check_data_residency.py` still
  passes (Lighthouse resources are tenant-level, no `location`); `tests/unit/
  test_lighthouse_onboarding.py` asserts the least-privilege role set, no forbidden roles,
  keyless-ness, and the placeholder GUIDs.

## Consequences

- **Positive.** The in-boundary guarantee is preserved for MSP-managed customers; onboarding is a
  single customer-run `az deployment sub create`; access is least-privilege, keyless, auditable, and
  customer-revocable; the MSP manages membership via Entra groups without re-onboarding.
- **Negative / deferred.** Subscription-wide vs single-RG scope is a customer choice (the RG variant
  is the narrower default). A custom **no-telemetry read role** (Finding1 Option A) is deferred as
  future hardening; until then Reader's telemetry-read residual is accepted and audited (Option B).
  Marketplace **offer publishing** (`plan` publisher/product/version) and
  **eligible PIM authorizations** (`justInTimeAccessPolicy`, `managedByTenantApprovers`) are left as
  `TODO(human):` — they need real publisher details / JIT policy sign-off and are out of scope here.
- **Follow-ups.** If a future capability genuinely needs a write action on customer infrastructure,
  it must go through a new ADR — this decision keeps the delegation **read-only** (guardrail #5: no
  auto-remediation).
