---
name: workload-author
description: Author Workload Definition Packs that teach Discovery how to classify an estate into workload → tier → role for Epic, SAP, Citrix or bespoke n-tier apps. Use when onboarding a new workload type or refining classification.
---

# Skill: workload-author

Teach the platform **what a workload is**. A Workload Definition Pack maps raw Azure resources
(and optional Kuiper hints) to `workload → tier → role`, which everything else builds on.

## Body shape
```json
{ "manifest": { "type": "workload", "id": "epic-core", "version": "1.0.0", "targets": ["epic"] },
  "body": { "workload": "epic",
    "definitions": [
      { "resourceType": "Microsoft.Compute/virtualMachines",
        "tagKey": "epic-role", "tagValue": "odb", "tier": "database", "role": "odb" },
      { "resourceType": "Microsoft.Network/loadBalancers", "tier": "presentation", "role": "lb" }
    ] } }
```
Discovery's pure `classify()` consumes `definitions` (see `src/modules/discovery/module.py`).

## Guidance
- Prefer **tag-based** matching; fall back to resource type + naming patterns.
- Model tiers generically (presentation / application / database / integration) so the same
  approach generalizes from Epic to SAP or a bespoke app.
- Keep role names stable — dependency and rule packs reference them.

## Definition of done
- [ ] Classifies a synthetic estate fixture correctly in a unit test
- [ ] Generic tiers; no proprietary schema leakage
- [ ] Validated + versioned
