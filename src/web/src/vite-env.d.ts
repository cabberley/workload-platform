/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Optional URL of an embedded telemetry panel (Grafana or Azure Workbooks). When unset (the
   * default), the console shows a documented placeholder instead of embedding anything.
   * No secrets: this must be a shareable/anonymous or auth-proxied panel URL, never a token.
   */
  readonly VITE_GRAFANA_PANEL_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
