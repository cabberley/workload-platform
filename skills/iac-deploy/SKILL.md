---
name: iac-deploy
description: Author and evolve Bicep infra so every module deploys as its own independently scalable ACA app/Job, plus the release build→deploy workflow. Use for infra/, scaling profiles, and azd. Enforces keyless (Managed Identity) and in-boundary deployment.
---

# Skill: iac-deploy

Own the infrastructure that makes **each module independently scalable** and deployable **inside
the customer subscription**.

## Golden rule
Every module is a **separate** ACA resource with its **own** KEDA scale rule, derived from its
`manifest.yaml::scaleProfile`. Never co-locate modules into one scaling unit.

## Files
- `infra/bicep/main.bicep` — orchestrator: core + a per-module stamp.
- `infra/bicep/modules/module-app.bicep` — a `kind: service` module → ACA app (HTTP/queue scale).
- `infra/bicep/modules/module-job.bicep` — a `kind: job` module → ACA Job (cron/queue, scale-to-zero).
- `infra/bicep/modules/core.bicep` — env, Log Analytics, Key Vault, identity, storage/queues, ACR.
- `.github/workflows/release.yml` — build+push images, then `az deployment group create`.

## Rules
- **Keyless.** User-assigned Managed Identity; ACR pull + Key Vault + storage via role assignments.
  No secrets in params or templates.
- **In-boundary.** Everything lands in the customer's subscription/RG. No cross-tenant egress.
- **Parameterize scale.** min/max replicas, triggers and resources come from the module manifest,
  not hard-coded.
- **What-if before deploy.** Keep the `what-if` step in the release workflow.

## Definition of done
- [ ] New/changed module has its own stamp in `main.bicep`
- [ ] Scale params flow from the manifest
- [ ] Keyless; `az bicep build` clean; what-if reviewed
