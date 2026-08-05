# Docs

The **source of intent** for this platform is the *Workloads Platform Blueprint* (16 documents,
codename *Aegis*). This repository implements that blueprint as a buildable scaffold.

- **`ARCHITECTURE.md`** (repo root) — binding architecture; how modules scale independently.
- **`../AGENTS.md`** — the multi-agent build model and roles.
- **`adr/`** — Architecture Decision Records; one decision per file.
- **`security/`** — security artifacts grounded in the code/infra:
  - **`security/threat-model.md`** — STRIDE-style threat model over the in-boundary architecture: trust boundaries, data flows, per-category threats + mitigations mapped to the platform guardrails, and tracked residual risks.
  - **`security/rbac-matrix.md`** — least-privilege RBAC matrix mapping each Azure interaction to the narrowest role, scope, and justification.
- **`observability.md`** — platform self-observability: health/readiness, internal metrics, tracing seams.
- **`telemetry-visualization.md`** — telemetry visualization on **Azure Managed Grafana** over Azure Monitor (keyless, in-boundary, no-PII boards). The deploy provisions the **instance, its public Entra-SSO endpoint, and the dedicated read-only Grafana identity's Monitor/LA read roles** (per-component identities, #79); the Azure Monitor **data source**, **dashboard import**, the **Grafana Editor** provisioning principal, and the console **deep-link** are **manual steps, not yet wired** (see the threat model §B12 / R13). See ADR `0007`.
- **`workload-generalization.md`** — proof the platform is workload-agnostic: a new workload type (Epic, SAP, Citrix, bespoke) is onboarded with **content packs only, no code change**.
- **`compliance/`** — **HITRUST CSF** control mapping + the in-boundary compliance guardrails (no-PII-egress audit, data-residency assertion). See `compliance/README.md`.
- **`delivery/`** — MSP / delivery playbooks. **`delivery/lighthouse-onboarding.md`** — **Azure Lighthouse** delegated resource management over **customer-owned** deployments (least-privilege read-only roles, keyless, boundary-preserving) with deploy/audit/revoke steps. See ADR `0011`.
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
