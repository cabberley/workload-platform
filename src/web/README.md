# Web console

React + Vite + TypeScript SPA. Reads the API's read models (`/api/*`) — it never writes state.

```bash
npm install
npm run dev      # http://localhost:5173 (proxies /api to http://localhost:8000)
npm run build    # production build to dist/
```

Roadmap: dependency-graph view with node health (up/degraded/down) and SPOF ranking by blast
radius, plus embedded Grafana/workbook panels for telemetry. See `skills/dashboard-author`.
