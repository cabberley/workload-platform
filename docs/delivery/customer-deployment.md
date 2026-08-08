# Customer deployment — guided, keyless deploy into your own subscription

> **Issue #67, Phase 1.** This is the **fast path** for a customer (or a Microsoft FastTrack / field
> engineer) to deploy the whole Aegis Workloads Platform into the customer's **own** Azure
> subscription and resource group. It is **keyless** (Managed Identity / your `az login`),
> **least-privilege**, **reproducible**, and **fail-closed**. **No secrets, keys, or connection
> strings** are ever entered or stored.
>
> For automated releases from GitHub, use the [`release`](../../.github/workflows/release.yml)
> workflow (OIDC). For turnkey self-service from the Marketplace, see the Phase-2 scaffold in
> [`infra/marketplace/`](../../infra/marketplace/README.md). For MSP-at-scale management over many
> customer-owned deployments, see [`lighthouse-onboarding.md`](./lighthouse-onboarding.md).

The platform is **in-boundary by construction**: everything runs in the customer's subscription and
no PHI/PII ever leaves the boundary. Each of the six modules is stamped as its **own**
independently-scalable Azure Container App / Job from its manifest scale profile (mirrored in
`infra/bicep/main.bicep`).

---

## 1. Prerequisites

- **Azure CLI** ≥ 2.60 (`az version`). For the `azd` path also install **Azure Developer CLI**
  (`azd version`).
- **Python 3.11+** on the machine running the deploy (used only by the post-deploy writer-boundary
  gate; no packages required).
- **A target subscription and region** you own. Pick one region — all resources are co-located there
  (data residency by construction; enforced by `scripts/check_data_residency.py`).
- **Sign in — keyless:**

  ```bash
  az login                       # device code / browser; or a Managed Identity / OIDC in CI
  az account set --subscription <subscription-id>
  ```

### Least-privilege roles the *deployer* needs

The templates create resources **and** their least-privilege role assignments, and the post-deploy
gate can *remove* a legacy state-writer assignment on a brownfield redeploy. The principal running
the deploy therefore needs, **scoped to the target resource group** (or subscription):

| Role | Why |
|------|-----|
| **Contributor** | Create the resource group, ACR, Container Apps, Storage, Key Vault, Grafana, identities; run `az acr build`. |
| **User Access Administrator** (or **Role Based Access Control Administrator**) | The Bicep assigns the per-component identities' RBAC roles (`Microsoft.Authorization/roleAssignments/write`), and the writer-boundary gate may `delete` a stray legacy assignment on redeploy. |

`Owner` also works but is broader than needed. **Subscription-wide discovery** additionally needs a
separate subscription-scope **Reader** grant on the worker identity — see
[`infra/bicep/README.md`](../../infra/bicep/README.md#-reader-scope-rg-scoped-deployment-vs-subscription-wide-discovery)
(deliberately not granted by the RG-scoped template).

### API authentication — Phase-1 posture (delivered default: `disabled`, fully internal)

**Phase-1 delivered default is `authMode = disabled`.** The delivery surfaces (azd
`main.parameters.json`, the `infra/deploy` scripts, and the Marketplace UI/`mainTemplate`) ship with
`authMode = disabled`, so the API does **not** require bearer tokens. This is the **supported Phase-1
bring-up**, and it is safe because the deployment is **fully internal — there is NO public endpoint
at all**:

- The **API** always uses **internal** Container Apps ingress (never internet-facing).
- The **web UI** *also* uses **internal** ingress under the delivered default. `main.bicep`
  **structurally couples** the web app's public exposure to the auth posture:
  `webIngressExternal = (authMode == 'required')`. So with `authMode = disabled`, the web app is
  **internal-only** too. This closes the review-67-v4 exposure path — a public web front door whose
  nginx proxies `/api/*` would otherwise reach the unauthenticated internal API. The invariant *"the
  public web front door is only ever open when the API enforces required auth"* now holds in **every**
  deployment path, not just by a default value.

**How you reach the internal web UI (no public endpoint).** Internal ACA ingress is reachable from
**inside the Container Apps environment's VNet**. Use any of:

- **VNet peering** from a network you control to the environment's VNet;
- a **VPN gateway** or **ExpressRoute** into that VNet;
- **Azure Bastion** or a **jumpbox VM** deployed in the VNet;
- a **private endpoint** / private DNS resolution to the internal ingress.

Then browse `https://<webFqdn>` from within that private network. Full turnkey support for
required-auth (public web + SPA sign-in) is tracked in **issue #127**.

> **Fail-closed code default is preserved.** `infra/bicep/main.bicep`'s own `authMode` parameter
> still defaults to `required`. Anyone deploying `main.bicep` **directly** (not via these delivery
> surfaces) gets `authMode = required` ⇒ the web app is public **and** the API enforces bearer auth.
> Only the *delivered* defaults are `disabled` (fully internal). Either way the invariant holds.

To harden to required-auth (and public web), see
**[Enable required auth (hardening)](#enable-required-auth-hardening)** below. These auth identifiers
are **not** secrets.

---

## 2. Parameters

All parameters are non-secret. `main.bicep` accepts:

| Parameter | Required | Default | Notes |
|-----------|----------|---------|-------|
| `location` | ✅ | `resourceGroup().location` | Single region for every resource. |
| `containerRegistry` | ✅ | — | ACR name (without `.azurecr.io`); globally unique; created if absent (admin disabled — keyless). |
| `imageTag` | — | `latest` | Tag of the `api`/`worker`/`web` images to deploy. |
| `manageStateImmutabilityPolicy` | — | `true` | Set `false` **only after** the state-container WORM policy is LOCKED out-of-band (Azure then rejects further updates). |
| `authMode` | — | `required` in `main.bicep`; **`disabled` as delivered** (Phase-1, #127) | `required` (fail-closed) or `disabled`. The delivery surfaces override to `disabled` (internal-only API); harden per §7. |
| `authTenantId` | required when `authMode=required` | `''` | Entra tenant GUID. |
| `authAudience` | required when `authMode=required` | `''` | API app registration Application ID URI / client id. |

---

## 3. Deploy

Choose **one** path. Both are keyless and reproducible; both call the same `infra/bicep/main.bicep`.

### Path A — scripted (recommended for field / FastTrack)

The scripts in [`infra/deploy/`](../../infra/deploy/) bootstrap the RG + ACR, build & push the three
images with **`az acr build`** (server-side — no local Docker, keyless push), deploy the Bicep, run
the API-only-writer gate, and print the endpoints. Everything is parameterized.

**Linux / macOS / WSL / Azure Cloud Shell:**

```bash
./infra/deploy/deploy.sh \
  -s <subscription-id> \
  -g <resource-group> \
  -l <location> \
  -r <acr-name> \
  --auth-tenant-id <tenant-guid> \
  --auth-audience api://aegis-workloads-platform
# add --what-if to preview without deploying; --skip-build to redeploy an existing tag
```

**Windows PowerShell:**

```powershell
./infra/deploy/deploy.ps1 `
  -Subscription <subscription-id> `
  -ResourceGroup <resource-group> `
  -Location <location> `
  -AcrName <acr-name> `
  -AuthTenantId <tenant-guid> `
  -AuthAudience api://aegis-workloads-platform
# add -WhatIfOnly to preview; -SkipBuild to redeploy an existing tag
```

### Path B — `azd provision` (with hooks)

`azure.yaml` wraps `infra/bicep/main.bicep`; `infra/bicep/main.parameters.json` maps the Bicep
parameters from `azd` environment variables (all non-secret). Lifecycle **hooks** make this a
genuinely working, keyless deploy — no manual image staging or post-steps required:

- **preprovision** ensures the ACR exists (admin disabled) and `az acr build`s **all three** images
  (`api`, `worker`, `web` — including the `worker` image the ACA Jobs need) into it.
- **postprovision** runs the API-only-writer boundary gate (same as the scripted path).

```bash
azd auth login
azd env new aegis
azd env set AZURE_LOCATION <location>
azd env set AZURE_RESOURCE_GROUP <resource-group>   # required: the RG-scoped template + preprovision hook deploy into THIS group
azd env set AZURE_CONTAINER_REGISTRY_NAME <acr-name>
# Phase-1 delivered default is authMode=disabled (internal-only API) — the two vars below are only
# needed when hardening to authMode=required (see §7 / issue #127):
azd env set WP_AUTH_TENANT_ID <tenant-guid>
azd env set WP_AUTH_AUDIENCE api://aegis-workloads-platform
# optional: azd env set WP_IMAGE_TAG <tag>   # extra traceability tag; deploy references :latest

azd provision        # ensure ACR + build all images (preprovision) -> deploy Bicep -> writer gate (postprovision)
```

> **`AZURE_RESOURCE_GROUP` is required.** `main.bicep` is resource-group–scoped, and the
> **preprovision** hook creates/uses this exact group (and the ACR inside it) before provisioning.
> If it is unset, the hook stops immediately with
> `set it first: azd env set AZURE_RESOURCE_GROUP <resource-group-name>` — set it as shown above and
> re-run `azd provision`.

> **Use `azd provision`, not `azd up`.** `azd up`/`azd deploy` also run azd's per-service image push,
> which needs each container app to carry an `azd-service-name` tag mapping — deliberately **not**
> wired here (it would diverge from the release.yml / scripted image model). The hooks above stage
> every image during `azd provision`, so `azd provision` is the supported, fully-working azd flow.
> The **scripted `infra/deploy` path (Path A) is the fully-supported turnkey Phase-1 path.**
> **`TODO(human):`** to enable end-to-end `azd up`, add `azd-service-name` tags to the api/web
> container apps and reconcile azd's injected image names with `main.bicep`'s `imageTag`.

> **Defaults.** `main.parameters.json` wires the environment-driven parameters above **and sets
> `authMode` explicitly to `disabled`** (the Phase-1 delivered default — Option 3, issue #127 — safe
> only because the API is internal-only). The optional `imageTag` (`latest`) and
> `manageStateImmutabilityPolicy` (`true`) fall back to `main.bicep`'s own defaults. Note
> `main.bicep`'s **own** `authMode` default remains `required` (fail-closed) for direct deployers —
> only the delivered params override it. To change these, use the Path-A script (which parameterizes
> all of them) or edit `main.bicep`. The hooks build images tagged `:latest` to match that default so
> the provisioned apps/jobs resolve them.

### Manual `az` (equivalent to the script's core step)

```bash
az deployment group create \
  --resource-group <resource-group> \
  --name wp-<image-tag> \
  --template-file infra/bicep/main.bicep \
  --parameters \
    location=<location> \
    containerRegistry=<acr-name> \
    imageTag=<image-tag> \
    authMode=required \
    authTenantId=<tenant-guid> \
    authAudience=api://aegis-workloads-platform
```

---

## 4. Enforce the API-only-writer boundary (brownfield safety)

Both the **scripts (Path A)** and **`azd provision` (Path B, postprovision hook)** run this
automatically. If you deploy with **manual `az`**, run it afterward so the **API identity is the
only state-store writer** (issues #79/#97). It is a **no-op** on a fresh environment and **fails
closed** if any other principal holds a state-write role:

```bash
outputs=$(az deployment group show -g <resource-group> -n wp-<image-tag> --query properties.outputs -o json)
SA_ID=$(echo "$outputs"  | python -c 'import json,sys;print(json.load(sys.stdin)["storageAccountId"]["value"])')
API_PID=$(echo "$outputs" | python -c 'import json,sys;print(json.load(sys.stdin)["apiIdentityPrincipalId"]["value"])')

PYTHONPATH=src python scripts/cleanup_verify_state_writers.py \
  --scope "$SA_ID" --resource-group <resource-group> --allow "$API_PID" --cleanup
```

---

## 5. Post-deploy verification

1. **Endpoints** — the script prints them; otherwise:

   ```bash
   az deployment group show -g <resource-group> -n wp-<image-tag> --query properties.outputs -o json
   ```

   Note `apiFqdn` (**internal ingress** — reachable only from inside the Container Apps
   environment), `webFqdn` (**internal** under the Phase-1 disabled default; **public** only when
   `authMode=required`), `grafanaEndpoint`.

2. **API health** — the API core uses **internal** ingress (not internet-facing), so it is **not**
   reachable with `curl` from your workstation. Verify it from **inside the boundary** instead —
   e.g. exec into a running container app in the same environment and curl the internal FQDN:

   ```bash
   # the API is internal-only; check it from within the Container Apps environment
   az containerapp exec -g <resource-group> -n wp-web \
     --command "curl -sf https://<apiFqdn>/api/health && echo OK"
   ```

   (With `authMode=required` the API validates tokens on state-mutating calls; `/api/health` stays
   reachable in-boundary.) **How the browser reaches the API:** the API has *no public ingress*, so
   the SPA (which runs in the customer's browser, outside the boundary) never calls it directly.
   Instead the **web** container's nginx **reverse-proxies same-origin `/api/*`** to the API's
   internal ingress: the browser calls `https://<webFqdn>/api/...`, nginx (in-boundary) forwards it
   to `https://<apiFqdn>/api/...`. `main.bicep` injects that internal target into the web app as
   `WP_API_BASE_URL` (derived from the API app's ingress FQDN — never a hardcoded host; see
   `infra/docker/nginx.conf.template`). This keeps the API **keyless and internal-only** while the
   deployed SPA's `/api/*` calls resolve — nginx adds no credentials and forwards your Entra bearer
   token unchanged.

3. **Web** — under the Phase-1 delivered default (`authMode=disabled`) the web UI uses **internal**
   ingress, so open `https://<webFqdn>` **from inside the environment's VNet** (VNet peering, VPN/
   ExpressRoute, Azure Bastion, a jumpbox, or a private endpoint — see §1). It becomes the **public**
   entry point (Entra SSO) only after hardening to `authMode=required` (§7), which flips web ingress
   to external automatically.

4. **Keyless posture** — confirm the ACR admin account is disabled and Storage shared-key access is
   off:

   ```bash
   az acr show -n <acr-name> --query adminUserEnabled          # => false
   az storage account show -g <resource-group> -n <wpst...> --query allowSharedKeyAccess   # => false
   ```

5. **Modules deployed** — each module is its own ACA app/Job:

   ```bash
   az containerapp list     -g <resource-group> --query "[].name" -o tsv   # wp-api, wp-web, wp-aiops, wp-alerts
   az containerapp job list -g <resource-group> --query "[].name" -o tsv   # wp-discovery, wp-quality-checks, wp-reassessments, wp-dependency-graph, wp-telemetry-export
   ```

   > Azure resource names allow only lowercase letters, digits and hyphens, so module ids with an
   > underscore are hyphenated for the **resource name** only (e.g. `quality_checks` → `wp-quality-checks`).
   > The worker still dispatches on the real underscore module id via its `WP_MODULE` env / `--module` arg.

6. **Data residency** (static gate, run from the repo — should exit 0):

   ```bash
   PYTHONPATH=src python scripts/check_data_residency.py
   ```

---

## 7. Enable required auth (hardening)

Phase-1 ships with `authMode = disabled` and a **fully internal** deployment (both the API and the
web UI use internal ingress — no public endpoint). Move to `authMode = required` to enforce Entra
bearer-token validation on every API request **and** open the web UI to the public internet. **Full
turnkey support for required-auth (SPA sign-in + role wiring end-to-end) is tracked in
[issue #127](https://github.com/aegis/workloads-platform/issues/127).**

> ⚠️ **`authMode` also controls public exposure (structural coupling).** `main.bicep` sets
> `webIngressExternal = (authMode == 'required')`, so setting `authMode = required` **automatically
> flips the web app to PUBLIC (external) ingress**; `authMode = disabled` keeps it internal-only.
> There is no separate "expose publicly" switch — and no way to get a public web front door while the
> API is unauthenticated. **Never** attempt to expose the web app (or the API) publicly while
> `authMode = disabled`; a publicly reachable web app proxies `/api/*` to the API, so that would put
> an unauthenticated data plane on the internet.

> **Required-auth needs the #127 last mile.** Because `authMode = required` also makes the web app
> public, the SPA and workers must complete the Entra "last mile" (issue #127) to actually function:
> the SPA needs MSAL sign-in (`VITE_AUTH_*` below) and the `Workloads.Reader`/`Workloads.Operator`
> app-role assignments must be in place for users and worker Managed Identities. **Hardening =
> public web + required bearer auth + #127 wiring**, as one coordinated step.

Hardening steps:

1. **Register the API in Entra** — create an app registration for the API; set its Application ID URI
   (e.g. `api://aegis-workloads-platform`). This is the `authAudience`. Record the directory
   (tenant) GUID — this is `authTenantId`. Both are non-secret identifiers.
2. **Define app roles** — on the API app registration, define two app roles:
   - `Workloads.Reader` — read-only access (status/list endpoints).
   - `Workloads.Operator` — state-mutating operations.
3. **Assign the roles** —
   - Assign `Workloads.Reader` / `Workloads.Operator` to the **SPA users** (via the Enterprise
     Application, per user or group) so signed-in operators get the right scope.
   - Assign the appropriate role to each **worker Managed Identity** that calls the API
     (e.g. the `ApiStateReader` read path) so service-to-service calls carry an authorized token.
4. **Configure the SPA build** — build the web image with these non-secret build args so the SPA
   acquires and attaches tokens:
   - `VITE_AUTH_ENABLED=true`
   - `VITE_AUTH_CLIENT_ID=<SPA app registration client id>`
   - `VITE_AUTH_TENANT_ID=<tenant guid>`
   - `VITE_AUTH_API_SCOPE=api://aegis-workloads-platform/.default` (the API scope the SPA requests)
5. **Redeploy with required auth** — set the delivery param to `required` and supply the identifiers
   (this flips the web app to public ingress automatically — see the coupling note above):
   - **Path A (script):** `--auth-mode required --auth-tenant-id <tenant-guid> --auth-audience api://aegis-workloads-platform`
     (PowerShell: `-AuthMode required -AuthTenantId <tenant-guid> -AuthAudience api://aegis-workloads-platform`).
   - **azd:** set `authMode = required` in `main.parameters.json` (or override it) and
     `azd env set WP_AUTH_TENANT_ID <tenant-guid>` / `azd env set WP_AUTH_AUDIENCE api://aegis-workloads-platform`.
   - **Marketplace:** choose **Required (fail-closed)** in the UI and supply tenant id + audience.

With `authMode = required` the web UI becomes publicly reachable and the API **refuses to serve**
until a valid tenant + audience are configured and callers present a valid Entra bearer token
(issue #64). The nginx `/api/*` proxy is unchanged — it forwards the caller's bearer token untouched
and injects no credentials of its own.

---

## Redeploy / upgrade

Re-run the same command with a new `imageTag` (the scripts default it to a UTC timestamp so each
deploy is uniquely identifiable). Deployments are incremental and idempotent; the writer-boundary
gate runs every time and fails closed on any regression.

## Teardown

```bash
az group delete --name <resource-group> --yes --no-wait
```

Deletes every platform resource. Because the platform is customer-owned and in-boundary, nothing
persists outside your subscription.
