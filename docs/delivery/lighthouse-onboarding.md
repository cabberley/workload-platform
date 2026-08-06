# Azure Lighthouse onboarding — MSP-at-scale over customer-owned deployments

> **Issue #66** · Parent epic **#17 (M4)** · IaC: [`infra/bicep/lighthouse/`](../../infra/bicep/lighthouse/) · Decision: ADR [`0011`](../adr/0011-msp-delivery-via-azure-lighthouse.md)

This page describes how a Managed Service Provider (MSP) manages **many customer-owned** Aegis
deployments at scale using **Azure Lighthouse delegated resource management**, and how a customer
grants, **audits**, and **revokes** that delegation.

## What Lighthouse delegated management is (and why the boundary holds)

Azure Lighthouse lets a customer **delegate scoped, role-based ARM access** over their own
subscription (or a single resource group) to an MSP's **managing tenant** — *without* creating
guest accounts, sharing credentials, or moving any resource. It works by projecting principals
(users / groups / service principals / managed identities) from the MSP tenant into the customer
tenant with **specific built-in roles at a specific scope**.

Two resources are created in the **customer** tenant:

| Resource | Scope | Purpose |
|----------|-------|---------|
| `Microsoft.ManagedServices/registrationDefinitions` | subscription | Declares the offer: which MSP tenant manages this, and with which roles |
| `Microsoft.ManagedServices/registrationAssignments` | subscription **or** resource group | Applies the delegation to that exact scope |

**The customer boundary is preserved by construction:**

- The deployment stays **customer-owned** — it runs in the customer's subscription; Lighthouse only
  adds *scoped read access* for the MSP tenant on top.
- Delegation is a **control-plane (ARM)** grant only. Lighthouse does **not** copy, mirror,
  replicate, or export any workload data, PHI/PII, or log bodies out of the customer tenant (**no
  bulk egress**), and Reader grants **no access** to patient data, raw log bodies, or
  secrets. The MSP can only make the ARM reads its granted roles allow, *inside* the customer's
  tenant — which, under Reader's `*/read`, **does** include reading workload **telemetry** (metric
  values + Log Analytics query results): the accepted ADR-0011 Option B residual, audited via
  `LAQueryLogs` (see "Auditing MSP access" below). So this is **no bulk data export**, not "the MSP
  can read nothing".
- It is **keyless**: pure Entra identity projection. There is **no** key, secret, SAS, connection
  string, or shared credential anywhere in the templates, parameters, or outputs. MSP operators
  authenticate from their own tenant with their own identities / Managed Identities.
- It is **least-privilege and fail-closed**: only the narrow read-only roles below are granted; the
  customer can revoke at any time and the MSP retains nothing afterwards.

This aligns with the platform guardrails: **in-boundary only** (#1), **keyless** (#3), **least
privilege** (#7), and **auditable provenance** (#8).

## Least-privilege roles granted — and why each is needed

The delegation grants **exactly one** built-in, **read-only** role, and it is **not** a deploy-time
parameter — the templates build the `authorizations` internally from a fixed, hardcoded allowlist
(fail-closed, guardrail #7). Only the MSP **principal identity** is supplied at deploy time:

| Role | `roleDefinitionId` | Why this platform needs it |
|------|--------------------|----------------------------|
| **Reader** | `acdd72a7-3385-48ef-bd42-f606fba81ae7` | Read-only estate **discovery** — Azure Resource Graph / resource metadata (id, type, tags) and control-plane `*/read`, incl. reading monitor resource *definitions* (alert rules, action groups, diagnostic settings). **Honest scope (ADR-0011 Option B):** `*/read` also permits reading metric values and Log Analytics query **results**, so the MSP principal *can* read telemetry — a residual that is **accepted** and compensated by **auditing** (see "Auditing MSP access" below), not prevented by role scoping. |

### Monitoring Reader is deliberately NOT delegated (least privilege kept at "Reader only")

Monitoring Reader (`43d0d8ad-25c7-4714-9337-8ba259a9fe05`) would **broaden** the grant: on top of
`*/read` it adds further data-plane monitoring actions (e.g.
`Microsoft.OperationalInsights/workspaces/search/action`, plus `Microsoft.Support/*`). We keep the
delegation to the single built-in **Reader** role, so we do **not** add that extra surface.

Being honest about Reader itself: Reader's `*/read` **already** lets the MSP principal read metric
values and Log Analytics query **results**, so it is **not** telemetry-free. We do not claim
otherwise. Under **ADR-0011 Option B** that telemetry-read residual is **accepted** and compensated
by **auditing** (see the "Auditing MSP access (compensating control)" section below); not broadening
to Monitoring Reader simply keeps least privilege at "Reader only".

**Never granted:** Owner, Contributor, or User Access Administrator. Because roles come from an
internal allowlist and not a parameter, a deployer **cannot inject** a write-capable role. This
platform only **reads** — it performs **no auto-remediation** of customer infrastructure
(guardrail #5). If a future scenario appears to need a broader role, add a `TODO(human):` and an ADR
for sign-off rather than over-granting.

> **MSP self-service off-boarding** via the built-in *Managed Services Registration assignment Delete
> Role* (`91c1777a-f3dc-4fae-b103-61d183457e46`) is **not** granted by default — the customer can
> always revoke unilaterally (see below), so adding it would only widen the delegation. Grant it only
> after sign-off (`TODO(human):`).

> The read-only role here mirrors the in-boundary worker identity's Reader grant documented in
> [`infra/bicep/README.md`](../../infra/bicep/README.md) and the
> [RBAC matrix](../security/rbac-matrix.md), so the MSP delegated principal is no more privileged
> than the platform's own in-subscription compute.

## Deploy — customer grants the delegation

Pick the **narrowest** scope that works:

- **One resource group** (preferred where the workload lives in a single RG) →
  [`resource-group.bicep`](../../infra/bicep/lighthouse/resource-group.bicep)
- **Whole subscription** (multi-RG estate) →
  [`subscription.bicep`](../../infra/bicep/lighthouse/subscription.bicep)

Both are deployed at **subscription** scope by an account with Owner (or `Microsoft.Authorization/
roleAssignments/write`) on the target subscription. Fill the example parameters
(`*.parameters.json`) with the **real** MSP managing tenant id (`managedByTenantId`) and the MSP
principal object id (`principalId`) — every GUID shipped in those files is a **clearly-fake
placeholder** (`0000…`, `1111…`). The delegated **role is not a parameter**: the templates grant
only the read-only Reader role from an internal allowlist, so no privileged role can be supplied.

Delegate a **single resource group**:

```bash
az login --tenant <CUSTOMER_TENANT_ID>
az account set --subscription <CUSTOMER_SUBSCRIPTION_ID>

az deployment sub create \
  --name aegis-lighthouse-rg \
  --location <region> \
  --template-file infra/bicep/lighthouse/resource-group.bicep \
  --parameters infra/bicep/lighthouse/resource-group.parameters.json \
  --parameters managedByTenantId=<MSP_TENANT_ID> delegatedResourceGroupName=<RG_NAME>
```

Delegate the **whole subscription**:

```bash
az deployment sub create \
  --name aegis-lighthouse-sub \
  --location <region> \
  --template-file infra/bicep/lighthouse/subscription.bicep \
  --parameters infra/bicep/lighthouse/subscription.parameters.json \
  --parameters managedByTenantId=<MSP_TENANT_ID>
```

> `--location` here is only where the **deployment metadata** is stored; the Lighthouse resources
> are tenant-level and have **no** regional data placement — no customer data is regionalised by
> this deployment.

### MSP side — register / publish the offer

The MSP does **not** deploy anything into the customer tenant. Its responsibilities:

1. Provide the customer with the **managing tenant id** (`managedByTenantId`) and the **object id**
   (+ display name) of the read-only MSP principal for `principalId` (typically one Entra **group**,
   so membership is managed MSP-side without re-onboarding). The customer supplies **only** this
   identity — the role (Reader) is fixed inside the template, not chosen at deploy time.
2. After the customer deploys, confirm the delegation appears under **My customers** in the Azure
   portal (Lighthouse) for the managing tenant, and that only the expected role/scope are present.
3. *(Optional)* Publish a **Managed Service offer** to Azure Marketplace for repeatable onboarding.
   `TODO(human):` supply the Marketplace **publisher / product / version** (`plan`) details if a
   Marketplace offer is desired — the templates intentionally omit `plan` so nothing fake ships.
4. *(Optional, off by default)* **Eligible (PIM / just-in-time)** authorizations are **not emitted**
   by these templates — eligible/PIM elevation requires a `justInTimeAccessPolicy` and approver
   policy sign-off. `TODO(human):` design the JIT policy (+ optional `managedByTenantApprovers`) and
   get sign-off before enabling any eligible authorization; until then nothing privileged is ever
   available just-in-time.

## Audit — how the customer sees what the MSP is doing

- **Delegation inventory:** Azure portal → **Service providers → Service provider offers** (customer
  side) lists every active delegation, its scope, and the exact roles granted. `az managedservices
  assignment list` and `az managedservices definition list` return the same, scriptably.
- **Administrative (write/delete/role) actions are logged — reads are NOT:** the customer's **Azure
  Activity Log** records control-plane **administrative CHANGES** (writes, deletes, role assignments)
  and the Lighthouse **delegation lifecycle**, tagged with the managing (MSP) tenant identity. It
  does **NOT** record read (GET) operations, so a read-only MSP's `*/read`, metric reads, and Log
  Analytics queries do **not** appear here (see the compensating-control section below for how the
  query residual is actually audited). For a read-only delegation, Activity Log is therefore most
  useful to catch any **administrative** action by the managing tenant — which must **never** happen
  under Reader and would mean the role set was widened (investigate immediately). Query it, or route
  it to the in-boundary Log Analytics workspace, e.g.:

  ```kusto
  // Surface any ADMINISTRATIVE (write/delete/role) action by the managing (MSP) tenant. For a
  // correct read-only Reader delegation this result set should be ~empty — ANY hit is a red flag
  // (privilege widened / unexpected write). NOTE: Activity Log does not log reads, so this will NOT
  // show the MSP's `*/read` / metric-read / LA-query activity.
  // AzureActivity.TenantId is the Log Analytics WORKSPACE id — NOT the caller's Entra tenant; the
  // caller's tenant lives in the JWT claims Activity Log captures in the `Claims` column.
  AzureActivity
  | extend ClaimsDyn = todynamic(Claims)   // `Claims` is a JSON string of the caller's JWT claims
  | extend CallerTenantId = tostring(ClaimsDyn["http://schemas.microsoft.com/identity/claims/tenantid"])
  | where CallerTenantId == "<MSP_MANAGING_TENANT_ID>"   // administrative actions by the MSP tenant
  | project TimeGenerated, Caller, CallerTenantId, OperationNameValue, ResourceGroup, ActivityStatusValue
  | order by TimeGenerated desc
  ```

  > `AzureActivity.TenantId` ≠ the caller's tenant — it is the workspace id; use the
  > `http://schemas.microsoft.com/identity/claims/tenantid` claim from `Claims_d` instead.

- **Any hit is a red flag.** Because the delegated role is **read-only**, the query above should
  return **nothing**. Any administrative/write operation by the managing tenant means the role set
  was widened beyond Reader — treat it as an incident and review the delegation immediately.

## Auditing MSP access (compensating control)

Under ADR [`0011`](../adr/0011-msp-delivery-via-azure-lighthouse.md) **Option B** the built-in
**Reader** role is accepted even though its read scope includes **telemetry reads** (metric values
and Log Analytics query results). Auditing is the accepted compensating control — but it must be the
**right** audit surface, because **Azure does not audit all reads the same way**:

- **Azure Activity Log does NOT record reads.** It logs control-plane **administrative changes**
  (writes/deletes/role actions) and the delegation lifecycle only. It will therefore **not** show the
  MSP principal's `*/read`, metric reads, or Log Analytics queries. Its value for a read-only
  delegation is to detect any **write/administrative** action by the managing tenant (see the Audit
  section above) — which must never occur under Reader.
- **Log Analytics queries ARE auditable — via the workspace `LAQueryLogs` audit category.** This is
  the real compensating control for the query residual: when enabled, every KQL query against a
  workspace (including those run by the delegated MSP principal) is recorded.
- **Metric-value reads (`Microsoft.Insights/metrics/read`) are NOT individually auditable.** Azure
  provides no per-read audit log for metric reads, so this portion of the accepted Option B residual
  is disclosed as an **accepted, unmonitored residual** — it cannot be alerted on. The only
  mitigations are **coarse**: narrow or remove the delegation scope, or adopt the deferred Option A
  custom no-telemetry read role.

### Audit Log Analytics queries by the MSP principal (`LAQueryLogs`)

To audit the MSP querying customer logs, the customer (customer-owned, advisory) enables the
**Audit (`LAQueryLogs`)** category via a **diagnostic setting on each Log Analytics workspace**,
sending it to a workspace / storage / SIEM they own. Then query `LAQueryLogs`, filtered to the MSP
principal / tenant. The GUIDs below are **clearly-fake placeholders**:

```kusto
// Every Log Analytics query run by the delegated MSP principal (requires the workspace `LAQueryLogs`
// Audit diagnostic setting to be enabled). AADObjectId is the caller's Entra object id.
let MspPrincipalObjectId = "11111111-1111-1111-1111-111111111111";  // MSP principal / group (FAKE)
let ManagingTenantId = "00000000-0000-0000-0000-000000000000";      // MSP managing tenant (FAKE)
LAQueryLogs
| where AADObjectId has MspPrincipalObjectId or AADTenantId == ManagingTenantId
| project TimeGenerated, AADObjectId, AADTenantId, QueryText, RequestTarget, ResponseCode
| order by TimeGenerated desc
```

Optionally alert (via a scheduled query alert on `LAQueryLogs`) when the MSP principal queries
sensitive workspaces, routed to the customer's **own** action group.

### What remains unmonitored

Metric-value reads are **not** individually auditable in Azure (no per-read log). This residual is
**accepted and unmonitored** under Option B; do **not** assume it can be alerted on. If it becomes
material, narrow/remove the delegation or adopt the deferred **Option A** custom no-telemetry role.

All of the above is **advisory and customer-owned** — the platform never auto-remediates
(guardrail #5); the audit data stays **in-boundary** in the customer's own workspace. The customer
can **revoke** (next section) at any time if activity looks wrong.

## Revoke — how the customer removes the delegation

The customer can **revoke at any time, unilaterally** — no MSP cooperation required:

- **Portal:** Service providers → Service provider offers → select the delegation → **Remove
  delegation**.
- **CLI:** delete the `registrationAssignment` (this immediately withdraws all delegated access):

  ```bash
  # Subscription-scoped delegation:
  az managedservices assignment list -o table
  az managedservices assignment delete --assignment <REGISTRATION_ASSIGNMENT_ID>

  # Resource-group-scoped delegation (the RG variant). `az managedservices assignment delete` has
  # NO `--scope` flag; target the RG explicitly, or delete by the fully-qualified resource id:
  az managedservices assignment list --resource-group <RG_NAME> -o table
  az managedservices assignment delete --resource-group <RG_NAME> --assignment <REGISTRATION_ASSIGNMENT_ID>
  # …or, equivalently, by full resource id:
  az resource delete --ids /subscriptions/<sub>/resourceGroups/<RG_NAME>/providers/Microsoft.ManagedServices/registrationAssignments/<REGISTRATION_ASSIGNMENT_ID>
  ```

Once the assignment is deleted, the MSP tenant loses **all** projected access instantly and retains
nothing — the customer boundary snaps fully closed. The customer can always perform this removal
unilaterally; the MSP self-service *Managed Services Registration assignment Delete Role*
(`91c1777a-f3dc-4fae-b103-61d183457e46`) is **not** granted by default, so no MSP-side deletion path
is delegated unless it is separately approved (`TODO(human):`).

## Validation

The templates compile clean with the same toolchain CI uses:

```bash
az bicep build --file infra/bicep/lighthouse/subscription.bicep --stdout
az bicep build --file infra/bicep/lighthouse/resource-group.bicep --stdout
```

The `platform guardrails` / `compliance` gates also scan these files: the data-residency check
(`scripts/check_data_residency.py`) passes because the Lighthouse resources are tenant-level and
carry **no** `location` (no regional data placement), and the secret/keyless scans pass because the
templates contain no keys, secrets, or connection strings. A Python unit test
(`tests/unit/test_lighthouse_onboarding.py`) asserts the least-privilege role set, the absence of
Owner/Contributor/UAA, keyless-ness, and the clearly-fake placeholder GUIDs.
