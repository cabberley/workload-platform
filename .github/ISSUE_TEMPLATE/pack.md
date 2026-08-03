---
name: New pack
about: Author or version a signed content pack (knowledge, not code)
title: "[pack] <type>/<name>: <summary>"
labels: ["pack", "agent:pack-author"]
---

## Pack type
- [ ] Workload Definition (`content/workloads`)
- [ ] Rule (`content/rules`)
- [ ] Telemetry (`content/telemetry`)
- [ ] Dependency (`content/dependencies`)
- [ ] Ops (`content/ops`)

## Target workload(s)
Epic / SAP / Citrix / bespoke — which tiers/roles?

## Content summary
What knowledge does this pack encode? (checks / signals / edges / routes)

## Versioning
- New pack version:
- Supersedes:
- Which workloads should it be pinned to?

## Guardrails
- [ ] No PHI/PII, no customer data, no proprietary IP — synthetic fixtures only
- [ ] Validates against schema (`scripts/validate_packs.py`)
- [ ] Will be signed (SHA-256 + HMAC) before release
