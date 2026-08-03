---
name: New module
about: Add or substantially change an independently-scalable capability module
title: "[module] <name>: <capability>"
labels: ["module", "agent:module-engineer"]
---

## Module
`src/modules/<name>`

## Capability
What does it do? Which pack type(s) does it consume/produce?

## Contract
- Inputs (from API/packs):
- Outputs (`AgentResponse` / domain models):

## Scale profile (must be independent)
- kind: job | service
- min → max replicas:
- KEDA trigger(s):
- resources (cpu/mem):
- rationale (why these numbers for flexible workload sizes):

## Definition of done
- [ ] Implements `Module` (`src/shared/module_base.py`)
- [ ] `manifest.yaml` with real `scaleProfile`
- [ ] Registered in API module registry
- [ ] Pure logic unit-tested (Azure-free)
- [ ] `infra/bicep/modules` deploys it as its own ACA app/Job
