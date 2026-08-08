# infra/marketplace — Azure Marketplace managed-application package (Phase 2 SCAFFOLD)

> **Issue #67, Phase 2 — scaffold now, complete later.** This directory packages the existing
> platform Bicep (`../bicep/main.bicep`) as an **Azure Marketplace managed application** for turnkey,
> self-service deploy into a customer's **own** subscription. It is a working scaffold: the
> template, UI and packaging steps are here. Two things remain before it is publishable: the
> **Marketplace publisher account / offer identity**, and the **container-image source + staging**
> decision — note the platform core **creates an empty ACR**, so a turnkey image pull does **not**
> work yet (see the TODOs below).

For the **guided, field/FastTrack deploy path available today** (`azd` or the scripted deploy), see
[`docs/delivery/customer-deployment.md`](../../docs/delivery/customer-deployment.md) — that is
Phase 1 and needs no publisher account.

## The offer (what a customer gets)

A **managed application** offer lets a customer deploy Aegis from the Marketplace with a guided UI,
into a **managed resource group in their own subscription**. Everything the platform provisions —
the six independently-scalable module ACA apps/Jobs, the API core + web, Azure Container Registry,
Log Analytics, Container Apps environment, Storage (shared-key access disabled), Key Vault, Managed
Grafana, and the per-component user-assigned Managed Identities with least-privilege RBAC — is
inherited **unchanged** from `../bicep/main.bicep`. The offer preserves every guardrail:

- **In-boundary / customer-owned.** All resources land in the customer's managed resource group,
  co-located in one region (data residency by construction).
- **Keyless.** Every component authenticates with its own Managed Identity; there are **no** secrets,
  keys, SAS, or connection strings anywhere in the package, UI, or its outputs.
- **Least-privilege, fail-closed.** The API identity is the only state-store writer; the API
  defaults to `authMode = required` (refuses to serve until an Entra tenant + audience are supplied).

## Package contents

| File | Role |
|------|------|
| `mainTemplate.bicep` | **Source of truth.** A thin wrapper that forwards the UI parameters into `../bicep/main.bicep`. |
| `mainTemplate.json` | **Generated** from `mainTemplate.bicep` (self-contained ARM — the artifact the Marketplace deploys). Regenerate whenever the platform Bicep changes: `az bicep build --file mainTemplate.bicep --outfile mainTemplate.json`. |
| `createUiDefinition.json` | The portal UI capturing the non-secret parameters (registry, image tag, auth mode/tenant/audience, WORM toggle). |
| `README.md` | This file. |

`mainTemplate.json` is a **self-contained** template (Bicep inlines the whole platform as nested
deployments — no external linked-template artifacts to stage), so the managed-app `.zip` is simply
`mainTemplate.json` + `createUiDefinition.json` (+ an optional `viewDefinition.json`, see TODO).

## Preview the UI

Paste `createUiDefinition.json` into the **Create UI Definition Sandbox**
(<https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/SandboxBlade>) to preview the form
without publishing.

## Build / validate locally

```bash
# 1. Regenerate the deployable ARM from the Bicep source of truth
az bicep build --file mainTemplate.bicep --outfile mainTemplate.json

# 2. Confirm both JSON artifacts are well-formed
python -m json.tool mainTemplate.json      > /dev/null && echo "mainTemplate.json OK"
python -m json.tool createUiDefinition.json > /dev/null && echo "createUiDefinition.json OK"
```

## Remaining work to publish (Phase 2 completion)

- **`TODO(human):` Marketplace publisher account / offer identity.** Publishing requires a
  **Partner Center** commercial-marketplace account (publisher id) and an **Azure Application offer**
  (offer id + plan id) under it. These are the only external inputs still required. Once available:
  create the *Azure application → Managed application* offer, upload the package `.zip`, set the
  authorizations (the publisher's management principal + role) and pricing/plan.
- **`TODO(human):` container image source + staging (UNRESOLVED).** As scaffolded, the platform core
  (`../bicep/modules/core.bicep`) **creates the ACR unconditionally** in the managed resource group,
  so at deploy time it is a **freshly-created, EMPTY registry** — a turnkey image pull does **not**
  work today, and a publisher-owned registry *name* cannot be reused here (ACR names are globally
  unique, so it would collide). A Marketplace deploy has **no build step**, so the `api`/`worker`/
  `web` images must be **STAGED into that newly-created ACR** as part of the deploy/onboarding. This
  is the unresolved Phase-2 decision and must be settled together with the publisher/offer identity —
  e.g. (a) add an ACR **import/build** step (deployment script) that copies the images from a
  **publisher-owned source registry** the deployment identity has `AcrPull` on into the managed ACR,
  or (b) stage the images during a guided onboarding step. Do **not** assume the images are already
  present — the created ACR starts empty.
- **`TODO(human):` optional `viewDefinition.json`** to surface the deployed endpoints
  (`apiFqdn` / `webFqdn` / `grafanaEndpoint` outputs) in the managed-app overview blade.
