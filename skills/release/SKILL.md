---
name: release
description: Cut a versioned release — sign packs, tag, and drive the build→Bicep-deploy workflow to an Azure subscription. Use to ship to Private Preview and beyond. Enforces reproducible, signed, in-boundary releases.
---

# Skill: release

Ship safely and reproducibly. A release builds the three images, signs the packs, and deploys the
Bicep infra to the target Azure subscription — all keyless.

## Steps
1. **Green main:** CI, security, and pack-validate all passing.
2. **Version:** bump `version` in `pyproject.toml` and any changed pack manifests (semver).
3. **Sign packs:** produce SHA-256 + HMAC for every changed pack; the Packs Engine verifies before
   execute. Never release an unsigned or mutated-in-place pack version.
4. **Tag + GitHub Release:** publishing the release triggers `.github/workflows/release.yml`:
   - builds & pushes `api`, `worker`, `web` images to ACR (tagged with the release),
   - runs `az deployment group what-if`, then `az deployment group create` on `infra/bicep/main.bicep`.
5. **Verify:** check the deployment outputs (endpoints) and `/api/health`.

## Guardrails
- **Keyless** end-to-end (OIDC to Azure; Managed Identity at runtime).
- **In-boundary:** deploy into the customer/target subscription only.
- **Reproducible:** image tag == release tag; record which pack versions shipped.
- Gate production deploys behind the `production` environment approval if configured.

## Definition of done
- [ ] Versions bumped; packs signed
- [ ] Release published; images built; what-if reviewed; deploy succeeded
- [ ] `/api/health` green post-deploy
