import { useEffect, useMemo, useState } from "react";
import { ApiError, fetchGraph } from "../api/client";
import type { WorkloadGraph } from "../api/types";
import type { AsyncState } from "../hooks/useAsync";
import { summariseGraph } from "./estate";
import { td, th, muted } from "../styles";

/** Max simultaneous `fetchGraph` requests. The estate loads N workloads' graphs through a bounded
 *  async pool so a large estate never fires N requests at once. Exported for tests. */
export const GRAPH_FETCH_CONCURRENCY = 5;

/** Per-row load state for one workload's graph. */
type RowState =
  | { status: "loading" }
  | { status: "error"; error: Error }
  | { status: "success"; data: WorkloadGraph };

/**
 * Bounded-concurrency loader: fetch every workload's graph through a small worker pool so at most
 * `concurrency` requests are in flight at once. Each result/failure is stored independently so one
 * workload's error/404 never blanks the estate (fail-closed per row).
 */
function useEstateGraphs(workloads: string[], concurrency: number): Record<string, RowState> {
  const [rows, setRows] = useState<Record<string, RowState>>({});
  // Re-run only when the actual set of workloads changes (stable across identical re-renders).
  const key = workloads.join("\u0000");

  useEffect(() => {
    let cancelled = false;
    setRows(Object.fromEntries(workloads.map((w) => [w, { status: "loading" as const }])));

    let next = 0;
    async function worker() {
      while (!cancelled) {
        const i = next++;
        if (i >= workloads.length) return;
        const w = workloads[i];
        try {
          const data = await fetchGraph(w);
          if (!cancelled) setRows((prev) => ({ ...prev, [w]: { status: "success", data } }));
        } catch (error) {
          if (!cancelled) {
            setRows((prev) => ({
              ...prev,
              [w]: {
                status: "error",
                error: error instanceof Error ? error : new Error(String(error)),
              },
            }));
          }
        }
      }
    }

    const pool = Math.min(concurrency, workloads.length);
    void Promise.all(Array.from({ length: pool }, () => worker()));

    return () => {
      cancelled = true;
    };
  }, [key, concurrency]);

  return rows;
}

/**
 * Estate-wide picture across ALL workloads. Derived purely from existing read-only endpoints
 * (`fetchWorkloads` upstream + one `fetchGraph` per workload) so no new backend surface is needed.
 * Graphs are fetched through a bounded async pool (see `useEstateGraphs`). Fail-closed: the
 * workloads list and each per-row graph handle loading / 404 / empty / error explicitly.
 */
export function EstateView({ state }: { state: AsyncState<string[]> }) {
  const workloads = state.status === "success" ? state.data : [];
  const rows = useEstateGraphs(workloads, GRAPH_FETCH_CONCURRENCY);

  if (state.status === "loading") {
    return <p style={muted}>Loading estate…</p>;
  }
  if (state.status === "error") {
    return (
      <p style={{ color: "crimson" }} role="alert">
        Could not load the estate ({state.error.message}). This is not an all-clear.
      </p>
    );
  }
  if (state.data.length === 0) {
    return (
      <p style={muted}>No workloads discovered yet. Run discovery to populate the estate.</p>
    );
  }

  return (
    <section aria-label="Estate">
      <p style={{ ...muted, marginTop: 0 }}>
        {state.data.length} workload{state.data.length === 1 ? "" : "s"} discovered. Dependency
        summary derived from each workload&apos;s graph (raw graph facts — not blast radius).
      </p>
      <table style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr>
            <th style={th}>Workload</th>
            <th style={{ ...th, textAlign: "right" }}>Nodes</th>
            <th style={{ ...th, textAlign: "right" }}>Edges</th>
            <th style={th}>Tiers</th>
            <th style={th}>Roles</th>
            <th style={th}>Dependencies</th>
          </tr>
        </thead>
        <tbody>
          {state.data.map((w) => (
            <EstateRow key={w} workload={w} rowState={rows[w] ?? { status: "loading" }} />
          ))}
        </tbody>
      </table>
    </section>
  );
}

/** One workload row — presentational; its graph is loaded by the parent's bounded pool. */
function EstateRow({ workload, rowState }: { workload: string; rowState: RowState }) {
  const summary = useMemo(
    () => (rowState.status === "success" ? summariseGraph(rowState.data) : null),
    [rowState],
  );

  if (rowState.status === "loading") {
    return (
      <tr>
        <td style={td}>{workload}</td>
        <td style={td} colSpan={5}>
          <span style={muted}>Loading graph…</span>
        </td>
      </tr>
    );
  }

  if (rowState.status === "error") {
    const noGraph = rowState.error instanceof ApiError && rowState.error.status === 404;
    return (
      <tr>
        <td style={td}>{workload}</td>
        <td style={td} colSpan={5}>
          {noGraph ? (
            <span style={muted}>No dependency graph yet — run the dependency module.</span>
          ) : (
            <span style={{ color: "crimson" }}>
              Graph unavailable ({rowState.error.message}). Not an all-clear.
            </span>
          )}
        </td>
      </tr>
    );
  }

  const s = summary!;

  // Fail-closed: a successful BUT EMPTY graph is absence of evidence, not a clean result. Surface it
  // distinctly so it never reads as an analysed, risk-free workload.
  if (s.nodeCount === 0) {
    return (
      <tr>
        <td style={td}>
          <strong>{workload}</strong>
        </td>
        <td style={{ ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>0</td>
        <td style={{ ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>0</td>
        <td style={td} colSpan={3}>
          <span style={{ color: "#b06000" }}>
            Empty graph — dependencies unverified (not an all-clear).
          </span>
        </td>
      </tr>
    );
  }

  // Fail-closed: nodes but ZERO edges is absence of dependency evidence, not verified redundancy.
  // It must NOT fall through to the populated-graph "all edges redundant"/"none" all-clear.
  if (s.edgeCount === 0) {
    return (
      <tr>
        <td style={td}>
          <strong>{workload}</strong>
        </td>
        <td style={{ ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{s.nodeCount}</td>
        <td style={{ ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>0</td>
        <td style={td}>{s.tiers.length > 0 ? s.tiers.join(", ") : <span style={muted}>—</span>}</td>
        <td style={td}>{s.roles.length > 0 ? s.roles.join(", ") : <span style={muted}>—</span>}</td>
        <td style={td}>
          <span style={{ color: "#b06000" }}>
            No dependency edges recorded — dependencies unverified (not an all-clear).
          </span>
        </td>
      </tr>
    );
  }

  return (
    <tr>
      <td style={td}>
        <strong>{workload}</strong>
      </td>
      <td style={{ ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{s.nodeCount}</td>
      <td style={{ ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{s.edgeCount}</td>
      <td style={td}>{s.tiers.length > 0 ? s.tiers.join(", ") : <span style={muted}>—</span>}</td>
      <td style={td}>{s.roles.length > 0 ? s.roles.join(", ") : <span style={muted}>—</span>}</td>
      <td style={td}>
        <div>
          {s.singlePathEdges > 0 ? (
            <>
              {s.singlePathEdges} single-path edge{s.singlePathEdges === 1 ? "" : "s"}{" "}
              <span style={muted}>(non-redundant)</span>
            </>
          ) : (
            <span style={muted}>all edges redundant</span>
          )}
        </div>
        {s.mostDependedOn && (
          <div style={{ fontSize: 12, color: "#5f6368", marginTop: 2 }}>
            most depended-on: <code style={{ fontSize: 11 }}>{s.mostDependedOn.name}</code>{" "}
            <span style={muted}>(non-redundant in-degree {s.mostDependedOn.inDegree})</span>
          </div>
        )}
      </td>
    </tr>
  );
}
