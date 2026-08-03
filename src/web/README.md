# Web console

React + Vite + TypeScript SPA. Reads the API's read models (`/api/*`) — it never writes state.

```bash
npm install
npm run dev      # http://localhost:5173 (proxies /api to http://localhost:8000)
npm run build    # tsc -b && vite build → production build to dist/
```

## Views

- **Workload selector** — populated from `GET /api/workloads` (loading / empty / error handled).
- **Dependency graph** — `GET /api/workloads/{w}/graph` rendered as a layered SVG. Redundant edges
  are solid, non-redundant edges dashed (single-path risk); a legend explains every cue.
- **Node health** (`up`/`degraded`/`down`/`unknown`) — derived from `GET /api/workloads/{w}/findings`:
  a node named by a failing finding takes its worst severity (high/critical → down, medium/low →
  degraded). Encoded by **shape + glyph + label + colour** — never colour alone.
- **Blast radius + SPOFs** — ranked from `GET /api/workloads/{w}/findings?module=dependency_graph`
  (highest blast radius first). Blast-radius math is **read from findings**, not recomputed in TS.
  SPOF nodes get a badge, thicker border and larger size scaled by blast radius.
- **Drift badge** (optional) — `GET /api/workloads/{w}/drift`.
- **Telemetry panel** (optional) — an iframe is rendered only when `VITE_GRAFANA_PANEL_URL` is set
  at build time; otherwise a placeholder shows. Grafana vs Azure Workbooks is an open decision
  (`TODO(human)` in `src/panels/GrafanaPanel.tsx`). No URL/secret is hardcoded.

The console is **read-only** — every call is a GET; the SPA never writes state.
