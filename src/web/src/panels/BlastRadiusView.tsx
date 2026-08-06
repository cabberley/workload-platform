import { useEffect, useMemo } from "react";
import { ApiError, fetchImpact } from "../api/client";
import type { ImpactResult, WorkloadGraph } from "../api/types";
import { useAsync, type AsyncState } from "../hooks/useAsync";
import { GraphView } from "../graph/GraphView";
import { Legend } from "../graph/Legend";
import type { NodeHealth, Spof } from "../graph/health";
import { SIM_BADGE } from "../graph/encodings";
import { card, muted, td, th } from "../styles";

/** Empty overlay so the graph never shows SPOF badges during a simulation (that's a live concept). */
const NO_SPOFS = new Map<string, Spof>();

type Props = {
  workload: string;
  /** The already-loaded live dependency graph (structure is shared with live health view). */
  graph: WorkloadGraph;
  /** The node being simulated as failed. */
  node: string;
  /** Pick a different node to simulate (click on the graph). Disabled while a fetch is in flight. */
  onSelectNode: (nodeId: string) => void;
  /** Return to the live-health view. */
  onClear: () => void;
  /** Report whether an impact fetch is in flight, so the parent can disable node selection. */
  onBusyChange?: (busy: boolean) => void;
};

/**
 * True when the impact was computed on the SAME topology we are displaying. `states` comes from a
 * single canonical `compute_impact` call keyed by every node id in the backend graph, so its key
 * set must equal the displayed graph's node-id set (and include `failedNode`). Node-set equality
 * is NECESSARY BUT NOT SUFFICIENT: an edge-only change (same nodes, different/removed edge) would
 * pass it, so we ALSO require the server-computed `graphRevision` (an opaque hash over nodes +
 * edges) to be present on BOTH sides and match exactly. A missing/empty revision is itself treated
 * as divergence (fail-closed) — we never fall back to node-set equality when a revision is absent.
 * When any check fails the persisted graph changed between the graph fetch and the impact fetch —
 * applying new-topology impact to an old render would be a false all-clear, so we withhold the
 * recolor (fail-closed). The web never hashes the graph itself (no TS/Python divergence); it just
 * compares the two opaque strings the SAME Python function produced.
 */
function topologyConsistent(graph: WorkloadGraph, impact: ImpactResult): boolean {
  // Edge-level staleness: the server-computed revisions are MANDATORY. A missing/empty revision on
  // either side is treated as divergence (fail-closed) — we never fall back to the insufficient
  // node-set-only check, which an edge-only change with unchanged node IDs would slip through.
  if (!graph.graphRevision || !impact.graphRevision) return false;
  if (graph.graphRevision !== impact.graphRevision) return false;
  const displayed = new Set(graph.nodes.map((n) => n.id));
  if (!displayed.has(impact.failedNode)) return false;
  const keys = Object.keys(impact.states);
  if (keys.length !== displayed.size) return false;
  for (const k of keys) if (!displayed.has(k)) return false;
  return true;
}

/** The effective render state after folding topology-consistency into the fetch lifecycle. */
type SimView =
  | { kind: "loading" }
  | { kind: "error"; error: Error }
  | { kind: "diverged" }
  | { kind: "ready"; data: ImpactResult };

function toSimView(state: AsyncState<ImpactResult>, graph: WorkloadGraph): SimView {
  if (state.status === "loading") return { kind: "loading" };
  if (state.status === "error") return { kind: "error", error: state.error };
  if (!topologyConsistent(graph, state.data)) return { kind: "diverged" };
  return { kind: "ready", data: state.data };
}

/**
 * Interactive "what breaks if node X is down" view (issue #56). Fetches the CANONICAL server-side
 * blast-radius impact for `node`, recolors the graph by the simulated states, and lists the
 * down/degraded fallout. Fail-closed: while loading, on any error (incl. 404 / unknown node), or
 * when the impact's topology diverges from the displayed graph, the graph is NOT recolored — nodes
 * render as "unknown", never a false all-clear, and an explicit message is surfaced. Mount with
 * `key={node}` so each new selection resets to loading AND aborts the prior in-flight request.
 */
export function BlastRadiusView({ workload, graph, node, onSelectNode, onClear, onBusyChange }: Props) {
  const impactState = useAsync<ImpactResult>(
    (signal) => fetchImpact(workload, node, signal),
    [workload, node],
  );
  const view = toSimView(impactState, graph);

  // Report busy state so the parent can disable the node picker while a computation is in flight
  // (superseded computations are cancelled via AbortSignal rather than allowed to pile up).
  const busy = view.kind === "loading";
  useEffect(() => {
    onBusyChange?.(busy);
    return () => onBusyChange?.(false);
  }, [busy, onBusyChange]);

  // Only a topology-consistent SUCCESS recolors the graph. Loading/error/diverged → empty map →
  // every node "unknown" (indeterminate), so a simulation view can never masquerade as live health
  // or an all-clear.
  const health: Map<string, NodeHealth> = useMemo(() => {
    if (view.kind !== "ready") return new Map();
    const states = view.data.states;
    const m = new Map<string, NodeHealth>();
    for (const n of graph.nodes) {
      m.set(n.id, { state: states[n.id] ?? "unknown", worstSeverity: null, failing: [] });
    }
    return m;
  }, [view, graph]);

  // Node selection is withheld while a fetch is in flight so rapid clicks can't queue extra work.
  const selectHandler = busy ? undefined : onSelectNode;
  // "Clear" is likewise guarded while busy so a rapid select→clear→select cycle can't start a new
  // simulation before the prior request settles. `busy` is derived from the fetch lifecycle and is
  // cleared in EVERY terminal state (success/error/diverged) and on abort (unmount cleanup below),
  // so the control can never get permanently stuck.
  const handleClear = () => {
    if (!busy) onClear();
  };

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          margin: "4px 0 12px",
          flexWrap: "wrap",
        }}
      >
        <span
          style={{
            display: "inline-block",
            background: SIM_BADGE.color,
            color: "#fff",
            borderRadius: 4,
            padding: "2px 8px",
            font: "700 12px system-ui, sans-serif",
          }}
        >
          {SIM_BADGE.glyph} {SIM_BADGE.label}
        </span>
        <span style={{ fontSize: 14 }} role="status">
          Simulating failure of <code>{node}</code>. Health shown is simulated, not live.
        </span>
        <button
          type="button"
          onClick={handleClear}
          disabled={busy}
          style={{
            marginLeft: "auto",
            padding: "6px 14px",
            fontSize: 14,
            borderRadius: 999,
            border: "1px solid #1a73e8",
            background: "#fff",
            color: "#1a73e8",
            fontWeight: 600,
            cursor: busy ? "not-allowed" : "pointer",
            opacity: busy ? 0.6 : 1,
          }}
        >
          Clear simulation · back to live health
        </button>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 2fr) minmax(280px, 1fr)",
          gap: 16,
          alignItems: "start",
        }}
      >
        <section style={{ ...card, overflowX: "auto" }} aria-label="Blast-radius simulation graph">
          {view.kind === "loading" && (
            <p style={muted} role="status">
              Simulating {node} failing… nodes are shown as “unknown” until it loads.
            </p>
          )}
          {view.kind === "error" && renderError(view.error, node)}
          {view.kind === "diverged" && renderDiverged()}
          <GraphView
            graph={graph}
            health={health}
            spofs={NO_SPOFS}
            onSelectNode={selectHandler}
            failedNode={node}
          />
        </section>

        <div style={{ display: "grid", gap: 16 }}>
          <section style={card}>{renderResults(view)}</section>
          <Legend showSimulation />
        </div>
      </div>
    </div>
  );
}

function renderError(error: Error, node: string) {
  const is404 = error instanceof ApiError && error.status === 404;
  return (
    <p style={{ color: "crimson", fontSize: 12 }} role="alert">
      {is404
        ? `Could not simulate ${node}: the graph or node is no longer available (404).`
        : `Could not simulate ${node} (${error.message}).`}{" "}
      Nodes are shown as “unknown”, not healthy — this is not an all-clear.
    </p>
  );
}

function renderDiverged() {
  return (
    <p style={{ color: "crimson", fontSize: 12 }} role="alert">
      The dependency graph changed since it was loaded, so this impact was computed on a different
      topology than the one shown. Reload to re-run the simulation. Nodes are shown as “unknown” —
      this is not an all-clear.
    </p>
  );
}

function renderResults(view: SimView) {
  if (view.kind === "loading") {
    return (
      <p style={muted} role="status">
        Computing blast radius…
      </p>
    );
  }
  if (view.kind === "error") {
    // Fail-closed: no impact numbers on error — never fall through to a "0 down" all-clear.
    return (
      <p style={{ color: "crimson", fontSize: 12 }} role="alert">
        Blast-radius impact unavailable ({view.error.message}). This is not an all-clear.
      </p>
    );
  }
  if (view.kind === "diverged") {
    // Fail-closed: withhold the (new-topology) numbers rather than pin them to an old render.
    return (
      <p style={{ color: "crimson", fontSize: 12 }} role="alert">
        Graph changed — reload to re-run the simulation. Blast-radius figures are withheld; this is
        not an all-clear.
      </p>
    );
  }

  const { failedNode, blastRadius, down, degraded } = view.data;
  return (
    <section aria-label="Blast-radius impact" style={{ minWidth: 280 }}>
      <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>
        {SIM_BADGE.glyph} Impact of failing <code>{failedNode}</code>
      </h3>
      <p style={{ margin: "0 0 12px", fontSize: 14 }}>
        Blast radius:{" "}
        <strong data-testid="blast-radius-count" style={{ fontVariantNumeric: "tabular-nums" }}>
          {blastRadius}
        </strong>{" "}
        node{blastRadius === 1 ? "" : "s"} go down.
      </p>

      <ImpactList label="Down" nodeIds={down} emptyText="No other nodes go down." tone="#a50e0e" />
      <ImpactList
        label="Degraded"
        nodeIds={degraded}
        emptyText="No nodes are degraded."
        tone="#b06000"
      />
    </section>
  );
}

function ImpactList({
  label,
  nodeIds,
  emptyText,
  tone,
}: {
  label: string;
  nodeIds: string[];
  emptyText: string;
  tone: string;
}) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontWeight: 700, fontSize: 13, color: tone, marginBottom: 4 }}>
        {label} ({nodeIds.length})
      </div>
      {nodeIds.length === 0 ? (
        <p style={{ ...muted, margin: 0 }}>{emptyText}</p>
      ) : (
        <table style={{ borderCollapse: "collapse", width: "100%" }}>
          <thead>
            <tr>
              <th style={th}>Node id</th>
            </tr>
          </thead>
          <tbody>
            {nodeIds.map((id) => (
              <tr key={id}>
                <td style={td}>
                  <code style={{ fontSize: 12 }}>{id}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
