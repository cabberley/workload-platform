import { useEffect, useMemo, useState } from "react";
import { ApiError, fetchDrift, fetchFindings, fetchGraph } from "../api/client";
import type { Finding, WorkloadGraph } from "../api/types";
import { useAsync, type AsyncState } from "../hooks/useAsync";
import { deriveHealth, rankSpofs, type NodeHealth, type Spof } from "../graph/health";
import { GraphView } from "../graph/GraphView";
import { Legend } from "../graph/Legend";
import { SpofPanel } from "./SpofPanel";
import { BlastRadiusView } from "./BlastRadiusView";
import { DriftBadge } from "./DriftBadge";
import { card, muted } from "../styles";

/** Loads the graph, findings and drift for one workload and renders the dependency + SPOF view. */
export function WorkloadView({ workload }: { workload: string }) {
  const graphState = useAsync<WorkloadGraph>(() => fetchGraph(workload), [workload]);
  // ALL findings drive per-node health; the module-filtered read drives SPOF ranking.
  const findingsState = useAsync<Finding[]>(() => fetchFindings(workload), [workload]);
  const spofFindingsState = useAsync<Finding[]>(
    () => fetchFindings(workload, "dependency_graph"),
    [workload],
  );
  const driftState = useAsync(() => fetchDrift(workload), [workload]);

  // The node whose failure is being simulated (null = live health). Selecting a node fetches the
  // CANONICAL server-side impact and recolors the graph; clearing returns to live health.
  const [simNode, setSimNode] = useState<string | null>(null);
  // True while the simulation's impact fetch is in flight — disables re-selection so rapid clicks
  // can't queue extra server-side traversals (the superseded request is also aborted).
  const [simBusy, setSimBusy] = useState(false);

  const graph = graphState.status === "success" ? graphState.data : null;

  // Fail-closed guard: if the graph reloads and no longer contains the simulated node, drop the
  // simulation rather than fetch an impact for a node that isn't there.
  useEffect(() => {
    if (simNode && graph && !graph.nodes.some((n) => n.id === simNode)) {
      setSimNode(null);
    }
  }, [simNode, graph]);

  // Fail-closed: SPOFs are ranked ONLY from a SUCCESSFUL fetch. A loading/failed request must never
  // collapse to "no SPOFs" (a false all-clear) — it stays empty AND the panel shows loading/error.
  const spofs: Spof[] = useMemo(
    () => (spofFindingsState.status === "success" ? rankSpofs(spofFindingsState.data) : []),
    [spofFindingsState],
  );
  // The SPOF highlight overlay is withheld until the fetch succeeds (no false-green node badges).
  const spofByNode = useMemo(
    () =>
      spofFindingsState.status === "success"
        ? new Map(spofs.map((s) => [s.nodeId, s]))
        : new Map<string, Spof>(),
    [spofFindingsState, spofs],
  );

  const simulating = simNode !== null && graph !== null;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "4px 0 12px" }}>
        <h2 style={{ margin: 0, fontSize: 18 }}>{workload}</h2>
        <DriftBadge state={driftState} />
      </div>

      {graph && graph.nodes.length > 0 && (
        <NodePicker graph={graph} value={simNode} onSelect={setSimNode} disabled={simBusy} />
      )}

      {simulating ? (
        <BlastRadiusView
          key={simNode}
          workload={workload}
          graph={graph}
          node={simNode}
          onSelectNode={setSimNode}
          onClear={() => setSimNode(null)}
          onBusyChange={setSimBusy}
        />
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(0, 2fr) minmax(280px, 1fr)",
            gap: 16,
            alignItems: "start",
          }}
        >
          <section style={{ ...card, overflowX: "auto" }} aria-label="Dependency graph">
            {renderGraph(graphState, findingsState, spofByNode, workload, setSimNode)}
          </section>

          <div style={{ display: "grid", gap: 16 }}>
            <section style={card}>{renderSpofPanel(spofFindingsState, spofs)}</section>
            <Legend />
          </div>
        </div>
      )}
    </div>
  );
}

/** Picker to choose a node to simulate failing (the empty option returns to live health). */
function NodePicker({
  graph,
  value,
  onSelect,
  disabled = false,
}: {
  graph: WorkloadGraph;
  value: string | null;
  onSelect: (nodeId: string | null) => void;
  disabled?: boolean;
}) {
  return (
    <label style={{ display: "block", margin: "0 0 12px", fontSize: 14 }}>
      Simulate a node failing:{" "}
      <select
        value={value ?? ""}
        disabled={disabled}
        onChange={(e) => onSelect(e.target.value === "" ? null : e.target.value)}
        style={{ fontSize: 14, padding: "4px 8px" }}
      >
        <option value="">— none (live health) —</option>
        {graph.nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.role ?? n.tier ?? n.name ?? n.id} ({n.id})
          </option>
        ))}
      </select>
      {disabled && (
        <span style={{ marginLeft: 8, fontSize: 12, color: "#5f6368" }} role="status">
          computing…
        </span>
      )}
    </label>
  );
}

function renderGraph(
  graphState: AsyncState<WorkloadGraph>,
  findingsState: AsyncState<Finding[]>,
  spofByNode: Map<string, Spof>,
  workload: string,
  onSelectNode: (nodeId: string) => void,
) {
  if (graphState.status === "loading") {
    return <p style={muted}>Loading dependency graph…</p>;
  }
  if (graphState.status === "error") {
    // 404 = no graph persisted yet: a friendly empty state, not an error.
    if (graphState.error instanceof ApiError && graphState.error.status === 404) {
      return (
        <p style={muted}>
          No dependency graph yet for <strong>{workload}</strong>. Run the dependency &amp; blast
          radius module to build one.
        </p>
      );
    }
    return <p style={{ color: "crimson" }}>Failed to load graph: {graphState.error.message}</p>;
  }

  const graph = graphState.data;
  if (graph.nodes.length === 0) {
    return (
      <p style={muted}>
        The dependency graph for <strong>{workload}</strong> is empty.
      </p>
    );
  }

  // Fail-closed: only overlay health from a SUCCESSFUL findings fetch. While loading or on error we
  // pass an EMPTY health map, so every node renders as "unknown" (indeterminate) — never a
  // false-green "up". A missing/failed health signal must not read as healthy.
  const health: Map<string, NodeHealth> =
    findingsState.status === "success"
      ? deriveHealth(graph.nodes, findingsState.data)
      : new Map();

  return (
    <>
      {findingsState.status === "loading" && (
        <p style={muted} role="status">
          Loading node health… nodes are shown as “unknown” until it loads.
        </p>
      )}
      {findingsState.status === "error" && (
        <p style={{ color: "crimson", fontSize: 12 }} role="alert">
          Node health unavailable ({findingsState.error.message}). Nodes are shown as “unknown”, not
          healthy.
        </p>
      )}
      <GraphView graph={graph} health={health} spofs={spofByNode} onSelectNode={onSelectNode} />
    </>
  );
}

function renderSpofPanel(state: AsyncState<Finding[]>, spofs: Spof[]) {
  if (state.status === "loading") {
    return (
      <p style={muted} role="status">
        Loading single points of failure…
      </p>
    );
  }
  if (state.status === "error") {
    // Do NOT fall through to SpofPanel's "no SPOFs" all-clear when the fetch failed (fail-closed).
    return (
      <p style={{ color: "crimson", fontSize: 12 }} role="alert">
        Could not load SPOF findings ({state.error.message}). Ranking unavailable — this is not an
        all-clear.
      </p>
    );
  }
  return <SpofPanel spofs={spofs} />;
}
