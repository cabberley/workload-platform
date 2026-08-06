import { useEffect, useState } from "react";
import { fetchModules, fetchPackAssignments, fetchWorkloads } from "./api/client";
import type { ModuleManifest, PackAssignment } from "./api/types";
import { useAsync } from "./hooks/useAsync";
import { WorkloadSelector } from "./panels/WorkloadSelector";
import { WorkloadView } from "./panels/WorkloadView";
import { ModulesTable } from "./panels/ModulesTable";
import { PackAssignmentsTable } from "./panels/PackAssignmentsTable";
import { GrafanaPanel } from "./panels/GrafanaPanel";
import { card, muted } from "./styles";

/**
 * In-boundary console. Reads the API read models only (no state writes from the SPA):
 *  - module list + independent scale ranges
 *  - a workload's dependency graph, per-node health, and SPOFs ranked by blast radius
 *  - an optional, config-driven telemetry panel slot
 */
export function App() {
  const workloadsState = useAsync<string[]>(fetchWorkloads, []);
  const [selected, setSelected] = useState<string | null>(null);

  const [modules, setModules] = useState<ModuleManifest[]>([]);
  const [modulesError, setModulesError] = useState<string | null>(null);

  const [assignments, setAssignments] = useState<PackAssignment[]>([]);
  const [assignmentsError, setAssignmentsError] = useState<string | null>(null);

  useEffect(() => {
    fetchModules()
      .then(setModules)
      .catch((e: unknown) => setModulesError(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => {
    fetchPackAssignments()
      .then(setAssignments)
      .catch((e: unknown) => setAssignmentsError(e instanceof Error ? e.message : String(e)));
  }, []);

  // Default to the first workload once the list arrives.
  useEffect(() => {
    if (selected === null && workloadsState.status === "success" && workloadsState.data.length > 0) {
      setSelected(workloadsState.data[0]);
    }
  }, [selected, workloadsState]);

  return (
    <main
      style={{ fontFamily: "system-ui, sans-serif", padding: 24, maxWidth: 1280, margin: "0 auto" }}
    >
      <h1 style={{ marginBottom: 4 }}>Workloads Platform</h1>
      <p style={{ color: "#5f6368", marginTop: 0 }}>
        In-boundary discovery, quality, dependency &amp; blast radius, AIOps and alerts —
        read-only console.
      </p>

      <section style={{ ...card, marginBottom: 20 }}>
        <WorkloadSelector state={workloadsState} selected={selected} onSelect={setSelected} />
      </section>

      {selected ? (
        // `key={selected}` remounts the subtree on selection change so every useAsync hook resets
        // to `loading` synchronously — React discards the previous workload's graph/health/SPOF/drift
        // state. This guarantees no render can paint one workload's success under another's heading
        // (fail-closed: a selection change never shows a stale green/all-clear view).
        <WorkloadView key={selected} workload={selected} />
      ) : (
        workloadsState.status === "success" &&
        workloadsState.data.length > 0 && (
          <p style={{ color: "#5f6368" }}>Select a workload to view its dependency graph.</p>
        )
      )}

      <div style={{ display: "grid", gap: 20, marginTop: 24 }}>
        <GrafanaPanel />

        <section style={card}>
          <h2 style={{ marginTop: 0, fontSize: 18 }}>Platform modules</h2>
          {modulesError && <p style={{ color: "crimson" }}>API unavailable: {modulesError}</p>}
          <ModulesTable modules={modules} />
        </section>

        <section style={card}>
          <h2 style={{ marginTop: 0, fontSize: 18 }}>Pack assignments</h2>
          <p style={{ ...muted, marginTop: 0 }}>
            Which pack version each workload is pinned to. Read-only — assignments are made via the
            API.
          </p>
          {assignmentsError && (
            <p style={{ color: "crimson" }}>API unavailable: {assignmentsError}</p>
          )}
          <PackAssignmentsTable assignments={assignments} />
        </section>
      </div>
    </main>
  );
}
