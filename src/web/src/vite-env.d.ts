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

  /**
   * Optional Entra (Azure AD) sign-in settings for the console (issue #64). All are NON-SECRET
   * public identifiers/URLs — the SPA is a public client and authenticates via PKCE, so a client
   * secret is NEVER read here. Sign-in is enabled only when a client id + API scope + an authority
   * (explicit, or derived from the tenant id) are all present; otherwise the console runs without
   * auth (the documented local/no-auth path). See `src/web/src/auth/config.ts`.
   */
  readonly VITE_AUTH_CLIENT_ID?: string;
  /** Entra tenant (directory) id; used to derive the authority when one is not given explicitly. */
  readonly VITE_AUTH_TENANT_ID?: string;
  /** Explicit Entra authority URL, e.g. `https://login.microsoftonline.com/<tenant>`. Non-secret. */
  readonly VITE_AUTH_AUTHORITY?: string;
  /** Scope requested for an API access token, e.g. `api://<api-app-id>/.default`. Non-secret. */
  readonly VITE_AUTH_API_SCOPE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
