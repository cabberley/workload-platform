# Docs

The **source of intent** for this platform is the *Workloads Platform Blueprint* (16 documents,
codename *Aegis*). This repository implements that blueprint as a buildable scaffold.

- **`ARCHITECTURE.md`** (repo root) — binding architecture; how modules scale independently.
- **`../AGENTS.md`** — the multi-agent build model and roles.
- **`adr/`** — Architecture Decision Records; one decision per file.
- **`observability.md`** — platform self-observability: health/readiness, internal metrics, tracing seams.
- **`telemetry-visualization.md`** — telemetry visualization on **Azure Managed Grafana** over Azure Monitor (keyless, in-boundary, no-PII boards + embedding). See ADR `0007`.
- **`workload-generalization.md`** — proof the platform is workload-agnostic: a new workload type (Epic, SAP, Citrix, bespoke) is onboarded with **content packs only, no code change**.
- **Blueprint** — kept outside the repo (no customer/proprietary content in git). Key docs:
  - 01 Executive Summary · 02 Solution Architecture · 03 Module Specifications
  - 06 Packs & Content Model · 08 Runtime Agents + Copilot build skills
  - 09 Repo Structure & Engineering Playbook · 10 Roadmap
  - 13 Multi-Workload Extensibility · 14 Dependency Graph & Blast Radius
  - 15 Proactive AIOps & Guided Remediation

## Module ↔ pack map (quick reference)

| Module | Consumes pack | Produces |
|--------|---------------|----------|
| Discovery | Workload Definition | estate (ResourceNode[]) |
| Quality Checks | Rule | Finding[] |
| Reassessments | — | drift |
| Dependency & Blast Radius | Dependency | WorkloadGraph, SPOFs |
| AIOps | Telemetry | detections, RCA |
| Alerts & Notifications | Ops | notifications |
