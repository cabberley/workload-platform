import { fetchModules } from "../api/client";
import type { ModuleManifest } from "../api/types";
import { useAsync } from "../hooks/useAsync";
import { muted, td, th } from "../styles";

/**
 * Module enable/disable console (issue #57).
 *
 * Lists every platform module and shows an enable/disable control per module, backed by the
 * EXISTING module-registry read surface (`GET /api/modules` → `ModuleManifest.enabled`). It reuses
 * the same read model the rest of the console already consumes; it does not fork a new one.
 *
 * READ-ONLY BY DESIGN — the toggle is rendered but disabled. `ModuleManifest.enabled` is today a
 * STATIC manifest field: there is NO runtime enable/disable *write* path in `main`
 * (`src/shared/module_base.py` `ModuleRegistry` has no mutator, and the API exposes no
 * enable/disable endpoint — only `POST /api/modules/{name}/run`). Per the guardrails we must NOT
 * invent an unvalidated write path or a fake endpoint, so the control surfaces the current state
 * and stays inert until the backend toggle exists.
 *
 * TODO(human): wire the toggle to a validated backend enable/disable surface once it exists. That
 * surface must live in `main` first — a store-backed registry mutator + an API route (e.g.
 * `POST /api/modules/{name}/enabled`) that flips the module on/off and emits the
 * `AuditAction.module_enabled` / `module_disabled` audit event reserved at
 * `src/shared/module_base.py` (`ModuleRegistry` TODO, issue #59). When it lands: add a keyless
 * `setModuleEnabled(name, enabled)` client call, enable the switch, and optimistically reflect the
 * server's confirmed state (fail closed — revert + surface on any non-2xx).
 */
export function ModuleControls() {
  const state = useAsync<ModuleManifest[]>(() => fetchModules(), []);

  if (state.status === "loading") {
    return <p style={muted}>Loading modules…</p>;
  }
  if (state.status === "error") {
    return (
      <p style={{ color: "crimson" }} role="alert">
        Could not load modules ({state.error.message}). This is not an all-clear — module state is
        unknown.
      </p>
    );
  }
  if (state.data.length === 0) {
    return <p style={muted}>No modules reported.</p>;
  }

  const enabledCount = state.data.filter((m) => m.enabled).length;

  return (
    <section aria-label="Module enable/disable">
      <p style={{ ...muted, marginTop: 0 }}>
        {enabledCount} of {state.data.length} module{state.data.length === 1 ? "" : "s"} enabled.
        Enable state reflects each module&apos;s manifest; the runtime toggle is read-only until a
        validated backend enable/disable surface exists.
      </p>
      <table style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr>
            <th style={th}>Module</th>
            <th style={th}>Kind</th>
            <th style={th}>Scale (min→max)</th>
            <th style={th}>State</th>
            <th style={{ ...th, textAlign: "right" }}>Enabled</th>
          </tr>
        </thead>
        <tbody>
          {state.data.map((m) => (
            <ModuleRow key={m.name} module={m} />
          ))}
        </tbody>
      </table>
    </section>
  );
}

/** One module row with an accessible — but disabled — enable/disable switch. */
function ModuleRow({ module }: { module: ModuleManifest }) {
  const on = module.enabled;
  return (
    <tr>
      <td style={td}>
        <strong>{module.displayName}</strong>
        <div style={{ ...muted, fontSize: 11 }}>
          <code>{module.name}</code>
        </div>
      </td>
      <td style={td}>{module.kind}</td>
      <td style={td}>
        {module.scaleProfile.minReplicas} → {module.scaleProfile.maxReplicas}
      </td>
      <td style={td}>
        <span style={{ color: on ? "#137333" : "#5f6368", fontWeight: 600 }}>
          {on ? "enabled" : "disabled"}
        </span>
      </td>
      <td style={{ ...td, textAlign: "right" }}>
        <button
          type="button"
          role="switch"
          aria-checked={on}
          aria-label={`${on ? "Disable" : "Enable"} ${module.displayName} (unavailable — no backend toggle)`}
          disabled
          title="Runtime enable/disable requires a validated backend surface (not yet available)"
          style={{
            appearance: "none",
            width: 40,
            height: 22,
            borderRadius: 999,
            border: "1px solid #bdbdbd",
            background: on ? "#c6e6c8" : "#e8eaed",
            position: "relative",
            cursor: "not-allowed",
            opacity: 0.7,
          }}
        >
          <span
            aria-hidden
            style={{
              position: "absolute",
              top: 2,
              left: on ? 20 : 2,
              width: 16,
              height: 16,
              borderRadius: "50%",
              background: "#fff",
              boxShadow: "0 1px 2px rgba(0,0,0,0.3)",
            }}
          />
        </button>
      </td>
    </tr>
  );
}
