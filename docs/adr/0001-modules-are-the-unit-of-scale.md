# 0001. Modules are the unit of capability and of scale

Date: 2025-01-01 · Status: accepted

## Context

The platform must serve workloads of very different sizes (a small clinic vs. a large hospital
estate; a single SAP system vs. a bespoke n-tier app). Capabilities differ in load shape:
Quality Checks is bursty and embarrassingly parallel; Alerts is always-on but light; AIOps must
stay warm and scale with signal volume. A monolith forces one scaling decision for all of them.

## Decision

Each capability is an independent **module** that:

- implements `Module` (`src/shared/module_base.py`) and ships a `manifest.yaml` with a
  `scaleProfile` (kind, min/max replicas, KEDA triggers, resources);
- is deployed as its **own** Azure Container App (services) or Container Apps Job (batch) via
  `infra/bicep/modules/module-app.bicep` / `module-job.bicep`, stamped by `main.bicep`;
- does **not** import other modules — coordination happens through the API core and packs.

The API core is the **single writer** of shared state; modules submit results to it, so the API
stays at low replica counts while compute-heavy modules scale (and scale to zero) freely.

## Consequences

- **+** Each module scales to the workload's size independently; idle jobs cost ~nothing.
- **+** Modules are separately deployable, versionable and testable; agents can own one lane.
- **+** Clear blast-radius for change: a module fault doesn't starve others.
- **−** More deployment units and a queue/orchestration seam to maintain.
- **−** Cross-module features require a contract change (serialized via the Architect + an ADR).
