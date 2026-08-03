---
name: dashboard-author
description: Build the React/Vite web console and telemetry dashboards (Azure Managed Grafana + workbooks) including dependency-graph and blast-radius visualizations. Use for src/web and dashboard-as-code. Consumes read models only.
---

# Skill: dashboard-author

Make the platform legible: an operator should see, at a glance, **what's failing, what it takes
down, and what to do**.

## Surfaces
- **Web console** (`src/web`, React + Vite + TypeScript): module status, findings, the dependency
  graph, and blast-radius highlighting. Reads the API's read models — **never** writes state.
- **Grafana / Azure Monitor workbooks** (dashboard-as-code under `infra/` or `content/ops`):
  telemetry trends and detections.

## Guidance
- **Grafana (Azure Managed Grafana)** for time-series telemetry; **workbooks** for resource-centric
  drill-downs. Keep dashboards as code so they ship with releases.
- Visualize the graph with node health (up/degraded/down) and **rank SPOFs by blast radius**
  (use `/api/modules` + graph read models).
- No secrets in the SPA; call the API with the platform identity/session, not embedded keys.
- Accessibility: color is not the only signal (icons/labels for health states).

## Definition of done
- [ ] Reads read models only; no direct state writes
- [ ] Graph + blast-radius view present and legible
- [ ] `npm run build` clean; no secrets in the bundle
