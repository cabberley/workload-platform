# Web console

React + Vite + TypeScript SPA. Reads the API's read models (`/api/*`) — it never writes state.

```bash
npm install
npm run dev      # http://localhost:5173 (proxies /api to http://localhost:8000)
npm run build    # tsc -b && vite build → production build to dist/
npm test         # vitest run (component + pure-logic tests, jsdom)
```

## Views

The console is organised as in-page tabs — **Estate**, **Workload**, **Findings**, **Drift** —
above the always-on module list and telemetry panel. Scoped tabs use the shared `WorkloadSelector`
and remount via `key={selected}` so a selection change resets child `useAsync` state (no stale
success is ever shown).

- **Estate** (`panels/EstateView.tsx`) — an estate-wide picture across ALL workloads. For each
  workload from `GET /api/workloads` it fetches `GET /api/workloads/{w}/graph` through a bounded
  async pool (max `GRAPH_FETCH_CONCURRENCY` requests in flight) and derives a factual dependency
  summary (node/edge counts, tiers/roles present, single-path/non-redundant edge count, and the
  most depended-on node by non-redundant in-degree — see the pure `panels/estate.ts`). These are
  raw graph facts only — **not** SPOF or blast-radius measures (canonical blast radius lives in
  `src/shared/blast_radius.py` and is consumed via its own read model, issue #56). A successful but
  empty graph is surfaced as "dependencies unverified" (fail-closed), distinct from the 404
  no-graph and error states. No new backend endpoint is added.
- **Workload selector** — populated from `GET /api/workloads` (loading / empty / error handled).
- **Dependency graph** — `GET /api/workloads/{w}/graph` rendered as a layered SVG. Redundant edges
  are solid, non-redundant edges dashed (single-path risk); a legend explains every cue.
- **Node health** (`up`/`degraded`/`down`/`unknown`) — derived from `GET /api/workloads/{w}/findings`:
  a node named by a failing finding takes its worst severity (high/critical → down, medium/low →
  degraded). Encoded by **shape + glyph + label + colour** — never colour alone.
- **Blast radius + SPOFs** — ranked from `GET /api/workloads/{w}/findings?module=dependency_graph`
  (highest blast radius first). Blast-radius math is **read from findings**, not recomputed in TS.
  SPOF nodes get a badge, thicker border and larger size scaled by blast radius.
- **Findings** (`panels/FindingsView.tsx`) — lists a workload's findings from
  `GET /api/workloads/{w}/findings` with an optional module filter. Every finding shows full
  provenance via the shared `panels/FindingRow.tsx`: title, module, severity, tri-state pass/fail
  (`passed === null` and `false` are BOTH non-passing — fail-closed), blast radius, its evidence
  (`SourceReference[]`), and `packId@packVersion` + `createdAt`.
- **Drift** (`panels/DriftView.tsx`) — the FULL `GET /api/workloads/{w}/drift` report: New failures,
  Recovered, Still failing (each a `FindingRow` list) plus Added / Removed nodes. The `DriftBadge`
  only summarises; this view shows every delta.
- **Drift badge** (optional) — `GET /api/workloads/{w}/drift`.
- **Telemetry panel** (optional) — an iframe is rendered only when `VITE_GRAFANA_PANEL_URL` is set
  at build time; otherwise a placeholder shows. Grafana vs Azure Workbooks is an open decision
  (`TODO(human)` in `src/panels/GrafanaPanel.tsx`). No URL/secret is hardcoded.

All read-model views fail closed: loading / 404 / empty / error are each surfaced explicitly and a
missing or failed fetch is never collapsed into a misleading "all clear".

The console is **read-only** — every call is a GET; the SPA never writes state.
