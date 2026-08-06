// Entra (Azure AD) sign-in provider for the console — MSAL-backed, keyless (public client + PKCE),
// and entirely OPTIONAL. When `readAuthConfig()` returns null (auth not configured) the provider is
// a no-op pass-through and the console runs locally without sign-in. When configured it initializes
// MSAL, tracks the signed-in account, and registers a bearer-token getter with the API client so
// every `/api/*` request carries a fresh access token for the API audience.
//
// Keyless: no client secret anywhere (the SPA authenticates via PKCE). Tokens are acquired silently
// from the MSAL cache per request and never persisted by our code or logged.

import {
  InteractionRequiredAuthError,
  PublicClientApplication,
  type AccountInfo,
  type Configuration,
} from "@azure/msal-browser";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";
import { setAuthTokenProvider } from "../api/client";
import { readAuthConfig, type WebAuthConfig } from "./config";

export interface AuthState {
  /** Whether Entra sign-in is configured/enabled for this build. */
  readonly enabled: boolean;
  /** Whether a user is signed in. Always `true` when auth is disabled (nothing to gate). */
  readonly signedIn: boolean;
  /** The signed-in account, or `null`. Carries only the display name/oid MSAL provides. */
  readonly account: AccountInfo | null;
  signIn(): Promise<void>;
  signOut(): Promise<void>;
}

const DISABLED: AuthState = {
  enabled: false,
  signedIn: true,
  account: null,
  signIn: async () => {},
  signOut: async () => {},
};

const AuthContext = createContext<AuthState>(DISABLED);

/** Access the current auth state (sign-in status + actions). */
export function useAuth(): AuthState {
  return useContext(AuthContext);
}

function buildMsal(config: WebAuthConfig): PublicClientApplication {
  const configuration: Configuration = {
    auth: {
      clientId: config.clientId,
      authority: config.authority,
      // Redirect back to the SPA origin; no secret is involved (public client + PKCE).
      redirectUri: window.location.origin,
    },
    cache: { cacheLocation: "sessionStorage", storeAuthStateInCookie: false },
  };
  return new PublicClientApplication(configuration);
}

/** Wrap the app; gates nothing itself (see `SignInGate`) but wires MSAL + the token seam. */
export function AuthProvider({ children }: { children: ReactNode }): ReactElement {
  const config = useMemo(() => readAuthConfig(), []);
  const msal = useMemo(() => (config ? buildMsal(config) : null), [config]);
  const [account, setAccount] = useState<AccountInfo | null>(null);
  // Auth-disabled builds are ready immediately; MSAL builds become ready after `initialize()`.
  const [ready, setReady] = useState<boolean>(config === null);

  const getToken = useCallback(async (): Promise<string | null> => {
    if (!msal || !config) {
      return null;
    }
    const active = msal.getActiveAccount() ?? msal.getAllAccounts()[0] ?? null;
    if (!active) {
      return null;
    }
    try {
      const result = await msal.acquireTokenSilent({ scopes: [config.apiScope], account: active });
      return result.accessToken;
    } catch (err) {
      if (err instanceof InteractionRequiredAuthError) {
        const result = await msal.acquireTokenPopup({ scopes: [config.apiScope], account: active });
        return result.accessToken;
      }
      // Fail closed: no token attached ⇒ the API returns 401 rather than the SPA silently proceeding.
      return null;
    }
  }, [msal, config]);

  useEffect(() => {
    if (!msal) {
      return;
    }
    let cancelled = false;
    void (async () => {
      await msal.initialize();
      const existing = msal.getAllAccounts();
      if (!cancelled && existing.length > 0) {
        msal.setActiveAccount(existing[0]);
        setAccount(existing[0]);
      }
      if (!cancelled) {
        setReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [msal]);

  useEffect(() => {
    if (!msal) {
      setAuthTokenProvider(null);
      return;
    }
    setAuthTokenProvider(getToken);
    return () => setAuthTokenProvider(null);
  }, [msal, getToken]);

  const signIn = useCallback(async () => {
    if (!msal || !config) {
      return;
    }
    const result = await msal.loginPopup({ scopes: [config.apiScope] });
    msal.setActiveAccount(result.account);
    setAccount(result.account);
  }, [msal, config]);

  const signOut = useCallback(async () => {
    if (!msal) {
      return;
    }
    await msal.logoutPopup();
    setAccount(null);
  }, [msal]);

  const value = useMemo<AuthState>(() => {
    if (!config) {
      return DISABLED;
    }
    return { enabled: true, signedIn: account !== null, account, signIn, signOut };
  }, [config, account, signIn, signOut]);

  if (!ready) {
    return <p style={{ fontFamily: "system-ui, sans-serif", padding: 24 }}>Loading…</p>;
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
