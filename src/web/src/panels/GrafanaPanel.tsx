import { card, muted } from "../styles";

/**
 * Embedded telemetry panel slot. Config-driven: an iframe is rendered ONLY when a
 * `VITE_GRAFANA_PANEL_URL` build-time env is provided; otherwise a documented placeholder shows.
 * Nothing is embedded by default and no real URL is hardcoded (no secrets in the bundle).
 *
 * TODO(human): the telemetry surface (Grafana vs Azure Workbooks) is an OPEN decision — see AIOps
 * (System Pulse + Azure Monitor). Once chosen, wire the panel URL via `VITE_GRAFANA_PANEL_URL`
 * (or rename the env accordingly) and confirm the panel is anonymous/auth-proxied — never embed a
 * token or key. In-boundary guardrail: the panel must not egress PHI/PII.
 */
export function GrafanaPanel() {
  const panelUrl = import.meta.env.VITE_GRAFANA_PANEL_URL;

  return (
    <section aria-label="Telemetry panel" style={card}>
      <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>Telemetry</h3>
      {panelUrl ? (
        <iframe
          title="Embedded telemetry panel"
          src={panelUrl}
          style={{ width: "100%", height: 360, border: "1px solid #e0e0e0", borderRadius: 6 }}
          sandbox="allow-scripts allow-same-origin"
          referrerPolicy="no-referrer"
          loading="lazy"
        />
      ) : (
        <p style={muted}>
          No telemetry panel configured. Set <code>VITE_GRAFANA_PANEL_URL</code> at build time to
          embed a Grafana or Azure Workbooks panel here. (Grafana vs Workbooks is an open decision.)
        </p>
      )}
    </section>
  );
}
