import { card, muted } from "../styles";

/**
 * Telemetry panel — Azure Managed Grafana over Azure Monitor (issue #58, ADR 0007). Config-driven,
 * keyless, fail-closed. Three states, in precedence order:
 *
 *  1. `VITE_GRAFANA_PANEL_URL` set → an OPTIONAL sandboxed iframe embed. Azure Managed Grafana
 *     BLOCKS framing by default (X-Frame-Options / CSP `frame-ancestors`, no portal toggle), so this
 *     path only works with an embeddable, in-boundary, AUTH-PROXIED panel URL — never a token in the
 *     URL. A sandbox cannot override the response's frame headers, so an unproxied Grafana URL here
 *     renders blank; prefer the deep-link below unless a proxy is in place.
 *  2. `VITE_GRAFANA_URL` set → the DEFAULT: a keyless deep-link that opens the boards in Managed
 *     Grafana in a new tab (Entra SSO). No framing, nothing embedded, no token.
 *  3. neither set → a documented placeholder (fail-closed).
 *
 * No real URL/token is hardcoded; boards are aggregate and PII-free (no PHI/PII egress).
 */
export function GrafanaPanel() {
  const panelUrl = import.meta.env.VITE_GRAFANA_PANEL_URL;
  const grafanaUrl = import.meta.env.VITE_GRAFANA_URL;

  return (
    <section aria-label="Telemetry panel" style={card}>
      <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>Telemetry</h3>
      {panelUrl ? (
        <iframe
          title="Embedded Managed Grafana panel"
          src={panelUrl}
          style={{ width: "100%", height: 360, border: "1px solid #e0e0e0", borderRadius: 6 }}
          sandbox="allow-scripts allow-same-origin"
          referrerPolicy="no-referrer"
          loading="lazy"
        />
      ) : grafanaUrl ? (
        <p style={{ margin: 0 }}>
          <a
            href={grafanaUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: "inline-block",
              padding: "6px 14px",
              fontSize: 14,
              borderRadius: 6,
              border: "1px solid #1a73e8",
              background: "#e8f0fe",
              color: "#1a73e8",
              fontWeight: 600,
              textDecoration: "none",
            }}
          >
            Open dashboards in Azure Managed Grafana ↗
          </a>
          <span style={{ ...muted, display: "block", marginTop: 6 }}>
            Opens in a new tab with Entra SSO (keyless). Managed Grafana blocks in-page framing by
            default, so the console links out instead of embedding.
          </span>
        </p>
      ) : (
        <p style={muted}>
          No telemetry surface configured. Set <code>VITE_GRAFANA_URL</code> at build time to
          deep-link to Azure Managed Grafana (keyless, Entra SSO). Optionally set{" "}
          <code>VITE_GRAFANA_PANEL_URL</code> to an embeddable, auth-proxied panel URL to embed a
          panel instead (never a token). Baseline boards are aggregate and PII-free.
        </p>
      )}
    </section>
  );
}
