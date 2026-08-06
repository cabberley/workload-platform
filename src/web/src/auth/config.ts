// Config-driven Entra (Azure AD) sign-in settings for the console. Keyless: only non-secret
// identifiers/URLs (client id, tenant/authority, the API scope) are read from Vite build/runtime
// env — NEVER a client secret (the SPA is a public client and uses PKCE). Sign-in is entirely
// OPTIONAL: `readAuthConfig` returns `null` when not configured, so the console still runs locally
// without auth, exactly like the backend gates auth off when its env is unset.

export interface WebAuthConfig {
  /** The console SPA's Entra app-registration client id (a public identifier, not a secret). */
  readonly clientId: string;
  /** The Entra authority URL (e.g. https://login.microsoftonline.com/<tenant>). Non-secret. */
  readonly authority: string;
  /** The scope requested for an API access token, e.g. `api://<api-app-id>/.default`. */
  readonly apiScope: string;
}

type ViteEnv = {
  readonly VITE_AUTH_CLIENT_ID?: string;
  readonly VITE_AUTH_TENANT_ID?: string;
  readonly VITE_AUTH_AUTHORITY?: string;
  readonly VITE_AUTH_API_SCOPE?: string;
};

/**
 * Read the console's Entra config from Vite env, or `null` when auth is not configured.
 *
 * Requires a client id + API scope and either an explicit authority or a tenant id (from which the
 * canonical authority is derived). Any missing piece ⇒ `null` (the documented no-auth local path).
 * Nothing here is a secret — a client id, tenant id, authority URL and scope are all public.
 */
export function readAuthConfig(env: ViteEnv = import.meta.env): WebAuthConfig | null {
  const clientId = (env.VITE_AUTH_CLIENT_ID ?? "").trim();
  const tenantId = (env.VITE_AUTH_TENANT_ID ?? "").trim();
  const apiScope = (env.VITE_AUTH_API_SCOPE ?? "").trim();
  const explicitAuthority = (env.VITE_AUTH_AUTHORITY ?? "").trim();
  const authority =
    explicitAuthority || (tenantId ? `https://login.microsoftonline.com/${tenantId}` : "");
  if (!clientId || !apiScope || !authority) {
    return null;
  }
  return { clientId, authority, apiScope };
}
