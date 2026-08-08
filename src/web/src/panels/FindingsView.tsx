import { useMemo, useState } from "react";
import { ApiError, fetchFindings } from "../api/client";
import type { Finding, RcaExplanationView } from "../api/types";
import { useAsync } from "../hooks/useAsync";
import { FindingRow } from "./FindingRow";
import { RcaExplanation } from "./RcaExplanation";
import { muted } from "../styles";

/**
 * Lists a workload's findings (quality-check + AIOps results) with full provenance. Fail-closed:
 * loading / error / 404 / empty are each surfaced explicitly — a missing or failed fetch is never
 * collapsed into a misleading "all clear".
 *
 * The optional module filter is client-side over a single fetch (the API also accepts a `module`
 * query param via `fetchFindings(workload, module)` if a server-side filter is ever preferred).
 *
 * `rcaExplanations` is the OPTIONAL grounded, advisory RCA explanation projection (issue #54),
 * joined from a module run result's `extra.rca` + `extra.rcaExplanation` via
 * `selectRcaExplanations`. It is advisory-only and renders nothing when absent — so the read-only
 * console stays graceful until/unless a run result is surfaced to it (the SPA never runs modules).
 */
export function FindingsView({
  workload,
  rcaExplanations = [],
}: {
  workload: string;
  rcaExplanations?: RcaExplanationView[];
}) {
  const state = useAsync<Finding[]>(() => fetchFindings(workload), [workload]);
  const [module, setModule] = useState<string>("");

  const modules = useMemo(
    () =>
      state.status === "success"
        ? Array.from(new Set(state.data.map((f) => f.module))).sort()
        : [],
    [state],
  );

  if (state.status === "loading") {
    return <p style={muted}>Loading findings…</p>;
  }
  if (state.status === "error") {
    if (state.error instanceof ApiError && state.error.status === 404) {
      return (
        <p style={muted}>
          No findings read model for <strong>{workload}</strong> yet. Run the quality-check / AIOps
          modules to populate it.
        </p>
      );
    }
    return (
      <p style={{ color: "crimson" }} role="alert">
        Could not load findings ({state.error.message}). This is not an all-clear.
      </p>
    );
  }

  const all = state.data;
  const shown = module ? all.filter((f) => f.module === module) : all;

  return (
    <section aria-label="Findings">
      <RcaExplanation views={rcaExplanations} />
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
        <label htmlFor="findings-module" style={{ fontWeight: 600, fontSize: 13 }}>
          Module
        </label>
        <select
          id="findings-module"
          value={module}
          onChange={(e) => setModule(e.target.value)}
          disabled={modules.length === 0}
          style={{ padding: "5px 8px", fontSize: 13, borderRadius: 6, border: "1px solid #ccc" }}
        >
          <option value="">All modules</option>
          {modules.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <span style={muted}>
          {shown.length} finding{shown.length === 1 ? "" : "s"}
        </span>
      </div>

      {all.length === 0 ? (
        <p style={muted}>
          No findings recorded for <strong>{workload}</strong>. This reflects an empty read model,
          not a verified pass.
        </p>
      ) : shown.length === 0 ? (
        <p style={muted}>No findings from module “{module}”.</p>
      ) : (
        <div style={{ display: "grid", gap: 10 }}>
          {shown.map((f) => (
            <FindingRow key={f.id} finding={f} />
          ))}
        </div>
      )}
    </section>
  );
}
