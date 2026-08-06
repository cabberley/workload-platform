import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { AuthProvider } from "./auth/AuthProvider";
import { SignInGate } from "./auth/SignInGate";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AuthProvider>
      <SignInGate>
        <App />
      </SignInGate>
    </AuthProvider>
  </React.StrictMode>
);
