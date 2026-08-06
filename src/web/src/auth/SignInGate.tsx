// Sign-in gate for the console. When Entra auth is enabled but no user is signed in, it renders a
// minimal sign-in prompt instead of the app. When auth is disabled (local/no-auth builds) it is a
// transparent pass-through, so nothing about the existing UI changes. When signed in it renders a
// small account bar (name + sign-out) above the app without redesigning the console itself.

import type { ReactElement, ReactNode } from "react";
import { useAuth } from "./AuthProvider";

const barStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "flex-end",
  gap: 12,
  padding: "6px 16px",
  fontFamily: "system-ui, sans-serif",
  fontSize: 13,
  borderBottom: "1px solid #e2e2e2",
};

const promptStyle: React.CSSProperties = {
  fontFamily: "system-ui, sans-serif",
  maxWidth: 480,
  margin: "15vh auto",
  padding: 24,
  textAlign: "center",
};

export function SignInGate({ children }: { children: ReactNode }): ReactElement {
  const { enabled, signedIn, account, signIn, signOut } = useAuth();

  if (enabled && !signedIn) {
    return (
      <main style={promptStyle}>
        <h1>Workloads Platform</h1>
        <p>Sign in with your organization account to access the console.</p>
        <button type="button" onClick={() => void signIn()}>
          Sign in
        </button>
      </main>
    );
  }

  if (!enabled) {
    return <>{children}</>;
  }

  return (
    <>
      <div style={barStyle}>
        <span>{account?.name ?? account?.username ?? "Signed in"}</span>
        <button type="button" onClick={() => void signOut()}>
          Sign out
        </button>
      </div>
      {children}
    </>
  );
}
