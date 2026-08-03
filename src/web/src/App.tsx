import { useEffect, useState } from "react";
import { fetchModules, fetchWorkloads } from "./api/client";
import type { ModuleManifest } from "./api/types";
import { useAsync, type AsyncState } from "./hooks/useAsync";
import { WorkloadSelector } from "./panels/WorkloadSelector";
import { WorkloadView } from "./panels/WorkloadView";
import { ModulesTable } from "./panels/ModulesTable";
import { GrafanaPanel } from "./panels/GrafanaPanel";
import { EstateView } from "./panels/EstateView";
import { FindingsView } from "./panels/FindingsView";
import { DriftView } from "./panels/DriftView";
import { card } from "./styles";

/** In-page sections. `estate` is estate-wide; the rest are scoped to the selected workload. */
type Tab = "estate" | "workload" | "findings" | "drift";

const TABS: { id: Tab; label: string; scoped: boolean }[] = [
  { id: "estate", label: "Estate", scoped: false },
  { id: "workload", label: "Workload", scoped: true },
  { id: "findings", label: "Findings", scoped: true },
  { id: "drift", label: "Drift", scoped: true },
];

/**
 * In-boundary console. Reads the API read models only (no state writes from the SPA):
 *  - module list + independent scale ranges
 *  - a workload's dependency graph, per-node health, and SPOFs ranked by blast radius
 *  - an optional, config-driven telemetry panel slot
 */
export function App() {
  const workloadsState = useAsync<string[]>(fetchWorkloads, []);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("estate");

  const [modules, setModules] = useState<ModuleManifest[]>([]);
  const [modulesError, setModulesError] = useState<string | null>(null);

  useEffect(() => {
    fetchModules()
      .then(setModules)
      .catch((e: unknown) => setModulesError(e instanceof Error ? e.message : String(e)));
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

      <nav
        aria-label="Console views"
        style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}
      >
        {TABS.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              aria-pressed={active}
              onClick={() => setTab(t.id)}
              style={{
                padding: "6px 14px",
                fontSize: 14,
                borderRadius: 999,
                border: active ? "1px solid #1a73e8" : "1px solid #ccc",
                background: active ? "#e8f0fe" : "#fff",
                color: active ? "#1a73e8" : "#3c4043",
                fontWeight: active ? 700 : 500,
                cursor: "pointer",
              }}
            >
              {t.label}
            </button>
          );
        })}
      </nav>

      <section style={card}>{renderTab(tab, selected, workloadsState)}</section>

      <div style={{ display: "grid", gap: 20, marginTop: 24 }}>
        <GrafanaPanel />

        <section style={card}>
          <h2 style={{ marginTop: 0, fontSize: 18 }}>Platform modules</h2>
          {modulesError && <p style={{ color: "crimson" }}>API unavailable: {modulesError}</p>}
          <ModulesTable modules={modules} />
        </section>
      </div>
    </main>
  );
}

/**
 * Render the active view. Scoped views require a selected workload and are wrapped with
 * `key={selected}` so a selection change remounts them — every child `useAsync` resets to
 * `loading` synchronously and no render can paint one workload's success under another's heading
 * (fail-closed: a selection change never shows a stale green/all-clear view).
 */
function renderTab(tab: Tab, selected: string | null, workloadsState: AsyncState<string[]>) {
  if (tab === "estate") {
    return <EstateView state={workloadsState} />;
  }
  if (!selected) {
    return (
      <p style={{ color: "#5f6368", margin: 0 }}>
        Select a workload above to view its {tab}.
      </p>
    );
  }
  switch (tab) {
    case "workload":
      return <WorkloadView key={selected} workload={selected} />;
    case "findings":
      return <FindingsView key={selected} workload={selected} />;
    case "drift":
      return <DriftView key={selected} workload={selected} />;
  }
}
