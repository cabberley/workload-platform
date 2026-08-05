# infra/bicep/lighthouse — Azure Lighthouse delegation (MSP-at-scale, issue #66)

Least-privilege **Azure Lighthouse delegated resource management** templates that let an MSP manage
**customer-owned** Aegis deployments at scale. Each customer keeps their own subscription and
deployment; Lighthouse projects the MSP's managing tenant in with **read-only, scoped ARM access**.
Lighthouse does **not** copy, mirror, replicate, or export any workload data, PHI/PII, secrets, or
configuration out of the customer tenant (**no bulk egress** — control-plane identity delegation
only), and it is **keyless** (Entra identity projection, no key/secret/SAS/connection string
anywhere). Reader grants **no access** to patient data, raw log bodies, or secrets. It does,
however, permit reading workload **telemetry** (metric values + Log Analytics query results) from
*within* the customer tenant via `*/read` — the accepted **ADR-0011 Option B** residual (see below),
so this is "no bulk data export", not "the MSP can read nothing".

| File | Scope | Delegates |
|------|-------|-----------|
| `subscription.bicep` | `subscription` | The whole customer subscription |
| `resource-group.bicep` | `subscription` (assignment projected to one RG) | A single customer resource group (narrowest) |
| `modules/registration-assignment.bicep` | `resourceGroup` | Nested assignment used by `resource-group.bicep` |
| `subscription.parameters.json` / `resource-group.parameters.json` | — | Example params (CLEARLY-FAKE placeholder GUIDs) |

## Least-privilege roles granted (built-in, read-only)

The delegated `authorizations` are **not** a deploy-time parameter — they are built **inside** the
templates from a fixed, hardcoded read-only allowlist (fail-closed, guardrail #7). Only the MSP
**principal identity** is supplied at deploy time, so no privileged role can ever be injected.

| Role | roleDefinitionId | Why |
|------|------------------|-----|
| Reader | `acdd72a7-3385-48ef-bd42-f606fba81ae7` | Read-only estate discovery (ARG / resource metadata) + control-plane `*/read`, incl. reading monitor resource *definitions* (alert rules, action groups, diagnostic settings). **Honest scope (ADR-0011 Option B):** `*/read` also permits reading metric values and Log Analytics query results, so the MSP principal can read telemetry; that residual is accepted and compensated by **targeted auditing** (LA-query reads via `LAQueryLogs`; metric-value reads stay unmonitored), **not** by role scoping. Activity Log records administrative CHANGES only — **not** reads |

**Monitoring Reader is deliberately NOT delegated (least privilege kept at "Reader only").**
Monitoring Reader would *broaden* the grant with further data-plane monitoring actions (e.g.
`Microsoft.OperationalInsights/workspaces/search/action`, plus `Microsoft.Support/*`) on top of
`*/read`. We keep the delegation to the single built-in **Reader** role. Be honest, though: Reader's
own `*/read` already permits reading metric values and Log Analytics query **results**, so the MSP
principal *can* read customer telemetry. Under **ADR-0011 Option B** that telemetry-read residual is
knowingly **accepted** and compensated by **targeted auditing**, *not* by role scoping. Be precise
about what that auditing can and cannot see: the **Azure Activity Log records administrative CHANGES
only (writes/deletes/role actions) — it does NOT log read (GET) operations**, so it will *not* show
the MSP's `*/read`, metric-value reads, or Log Analytics query reads. Its value here is to surface
any **write/administrative** action by the managing tenant (which must never occur under Reader — a
hit signals the role set was widened; investigate) plus the delegation lifecycle; for a correct
read-only setup it is expected to be **~empty**. Log Analytics **query** reads are auditable
separately by enabling the workspace **`LAQueryLogs`** diagnostic setting (filter by the MSP
`AADObjectId`/tenant). **Metric-value reads remain individually unauditable / unmonitored** — Azure
provides no per-read log for `Microsoft.Insights/metrics/read`; only coarse mitigations exist
(narrow/remove the delegation, or adopt the deferred Option A custom no-telemetry role), and it is
**not** alertable (see the onboarding doc). Not broadening to Monitoring Reader preserves least
privilege at "Reader only".

Owner / Contributor / User Access Administrator are **never** granted (guardrail #7) and **cannot**
be supplied — the role set is hardcoded, not parameterized. Anything beyond Reader must be justified
with a `TODO(human):` and an ADR, not silently over-granted.

> **MSP self-service off-boarding** (via the built-in *Managed Services Registration assignment
> Delete Role*, `91c1777a-f3dc-4fae-b103-61d183457e46`) is **not** granted by default — the customer
> can always revoke unilaterally (see the onboarding doc). Granting it would widen the delegation, so
> it is left as a `TODO(human):` pending sign-off.

## Parameters (safe shape)

Neither entry template accepts a free-form `authorizations` array. The inputs are just:

| Parameter | Both templates | Notes |
|-----------|----------------|-------|
| `mspOfferName` / `mspOfferDescription` | default provided | Shown in the customer's *Service provider offers* blade |
| `managedByTenantId` | required | The MSP managing tenant GUID (real value at deploy time) |
| `principalId` | required | Object id of the MSP Entra **group** that receives Reader |
| `principalIdDisplayName` | default provided | Display name for that principal |
| `delegatedResourceGroupName` | `resource-group.bicep` only | The single RG to delegate |


## Deploy / audit / revoke

Full step-by-step onboarding, auditing and revocation instructions are in
[`docs/delivery/lighthouse-onboarding.md`](../../../docs/delivery/lighthouse-onboarding.md). See also
ADR [`0011`](../../../docs/adr/0011-msp-delivery-via-azure-lighthouse.md).
