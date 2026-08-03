# Security & Trust Model

Trust is the product. These rules are **non‑negotiable** and are enforced by
`.github/copilot-instructions.md`, the `security-review` skill, and the PR security workflow.

## Data boundary

- **In‑boundary by construction.** All runtime components deploy into the **customer's** Azure
  subscription. PHI/PII, log bodies, and workload configuration are processed and stored **only**
  in the customer boundary.
- **Only signed content flows in.** Packs (workload/rule/telemetry/dependency/ops) are the *only*
  inbound artifact. They carry knowledge, never data.
- **Nothing sensitive flows out.** Optional, explicitly opted‑in, **aggregated and PII‑free**
  findings may be exported. Default is no egress.
- **No PHI/PII in this repository** — no customer data, no sample patient/records data, no
  captured logs. No Epic/SAP proprietary IP or SDKs are vendored here.

## Identity & secrets

- **Keyless everywhere.** Managed Identity via `DefaultAzureCredential`. No connection strings,
  keys, or tokens in code, config, or packs.
- Secrets that must exist at runtime live in **Key Vault**, referenced by identity.
- CI uses **OIDC federation** to Azure — no long‑lived cloud credentials in GitHub secrets.

## Fail‑closed behavior

- Unknown or invalid **pack signature** → refuse to execute.
- Unknown resource type, missing evidence, or **low confidence** → surface for a human, do not
  act on it.
- **No automatic remediation** of customer infrastructure. AIOps proposes; humans dispose.
  Remediation guidance is advisory (with a "call support" path), never auto‑applied.

## Pack integrity

- Packs are hashed (**SHA‑256**) and signed (**HMAC**); the Packs Engine **verifies before
  execute**. Version pinning records which pack version ran against which workload (auditable).

## Multi‑tenant isolation (MSP model)

- Strict per‑client isolation (partition/row scoping + RBAC). A client can never read another
  client's data. Customer‑owned + **Azure Lighthouse** is preferred where possible.

## Reporting a vulnerability

Internal Microsoft process: file a private security issue and tag the Security/Release owner in
`.github/CODEOWNERS`. Do **not** open a public issue. The PR security workflow
(`.github/workflows/security.yml`) runs CodeQL, dependency review, secret scanning and the
`security-review` skill on every pull request.
