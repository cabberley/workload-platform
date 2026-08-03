/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Optional deep-link URL to the Azure Managed Grafana instance (decision resolved, ADR 0007).
   * This is the DEFAULT telemetry surface: the console renders an "Open in Managed Grafana" link
   * (new tab, Entra SSO) rather than an iframe, because Managed Grafana blocks framing by default.
   * Keyless: a plain instance/dashboard URL, never a token or API key.
   */
  readonly VITE_GRAFANA_URL?: string;

  /**
   * Optional URL of an EMBEDDABLE, auth-proxied Azure Managed Grafana panel (ADR 0007). Only set
   * this when an in-boundary auth proxy makes the panel frameable — Managed Grafana blocks framing
   * by default, so a raw instance URL here renders blank. When unset the console deep-links via
   * `VITE_GRAFANA_URL` (or shows a placeholder). Keyless: never a token or API key.
   */
  readonly VITE_GRAFANA_PANEL_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
