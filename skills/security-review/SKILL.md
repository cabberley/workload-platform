---
name: security-review
description: Review PRs and designs against the platform trust model — in-boundary, keyless, fail-closed, no PHI/PII, least privilege, pack integrity. Use on every PR and before any release. Backs the security.yml workflow.
---

# Skill: security-review

Trust is the product. This skill is the human+agent gate behind
`.github/workflows/security.yml`. Block anything that weakens the boundary.

## Checklist (fail the review on any miss)
- **In-boundary:** no new egress of PHI/PII, log bodies, or workload config. Only signed packs in;
  only opt-in, aggregated, PII-free findings out.
- **No secrets:** keyless (Managed Identity); no keys/connection strings/tokens in code, config,
  packs, or tests. Runtime secrets via Key Vault by identity. CI uses OIDC, not stored creds.
- **Fail-closed:** invalid pack signature → refuse; unknown/low-confidence → surface, don't act.
- **No auto-remediation** of customer infrastructure — advisory only.
- **Least privilege:** narrowest Azure RBAC role; justification present.
- **Pack integrity:** SHA-256 content hash + detached **Ed25519** signature over canonical bytes,
  verified before execute (keyless, offline signing); versions pinned/auditable.
- **No PHI/PII/proprietary IP** committed — synthetic fixtures only.
- **Multi-tenant isolation** (MSP): per-client partitioning/RBAC; no cross-client visibility.

## How to review
1. Read the diff against the checklist above and `SECURITY.md`.
2. Confirm CodeQL / dependency-review / secret-scan / guardrail jobs are green.
3. For anything ambiguous, request changes with a specific guardrail citation.

## Definition of done
- [ ] All checklist items pass or are explicitly, safely justified
- [ ] `security.yml` green; no new high/critical findings
