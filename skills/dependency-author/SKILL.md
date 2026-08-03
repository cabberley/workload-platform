---
name: dependency-author
description: Author Dependency Packs that declare entity dependencies (e.g. ECP nodes depend on the Epic ODB; VMs depend on a load balancer) with redundancy semantics, powering smart blast-radius analysis. Use to accelerate custom dependencies beyond what auto-derivation finds.
---

# Skill: dependency-author

Declare **what depends on what** so the platform can compute **smart blast radius**. Auto-derivation
already finds LB/App Gateway backend pools, private links and replication; use a Dependency Pack to
capture the rest (e.g. "ECP utility servers depend on the ODB server").

## Body shape
```json
{ "manifest": { "type": "dependency", "id": "epic-core-deps", "version": "1.0.0", "targets": ["epic"] },
  "body": { "edges": [
    { "source": "role:ecp", "target": "role:odb", "type": "depends_on", "redundant": false },
    { "source": "role:web", "target": "role:lb",  "type": "load_balances", "redundant": true }
  ] } }
```
Edges resolve against nodes discovered by the Workload Definition Pack (by role/tier/id).

## Redundancy semantics (critical)
- `redundant: false` → losing the target **downs** the source (and its dependents).
- `redundant: true` → the source has peers; losing one peer is **degraded**, losing the shared
  target (e.g. the LB) is **down**.
This is exactly what `shared.blast_radius.compute_impact` encodes.

## Definition of done
- [ ] Edges resolve to real roles/nodes
- [ ] Redundancy set intentionally on every edge
- [ ] A unit test asserts the expected blast radius on a synthetic graph
- [ ] Validated + versioned
