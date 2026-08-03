import type { AsyncState } from "../hooks/useAsync";
import type { DriftReport } from "../api/types";

/** Small drift badge summarising change vs the last snapshot. Silent on load/error (optional). */
export function DriftBadge({ state }: { state: AsyncState<DriftReport> }) {
  if (state.status !== "success") return null;

  const { newFailures, recovered, addedNodes, removedNodes } = state.data;
  const nothing =
    newFailures.length === 0 &&
    recovered.length === 0 &&
    addedNodes.length === 0 &&
    removedNodes.length === 0;

  return (
    <span
      title="Change vs the previous snapshot"
      style={{
        display: "inline-flex",
        gap: 8,
        alignItems: "center",
        border: "1px solid #e0e0e0",
        borderRadius: 999,
        padding: "3px 10px",
        fontSize: 12,
        background: "#fff",
      }}
    >
      <strong>Drift</strong>
      {nothing ? (
        <span style={{ color: "#137333" }}>● no change</span>
      ) : (
        <>
          {newFailures.length > 0 && (
            <span style={{ color: "#a50e0e" }}>▲ {newFailures.length} new failing</span>
          )}
          {recovered.length > 0 && (
            <span style={{ color: "#137333" }}>▼ {recovered.length} recovered</span>
          )}
          {(addedNodes.length > 0 || removedNodes.length > 0) && (
            <span style={{ color: "#5f6368" }}>
              ±nodes +{addedNodes.length}/-{removedNodes.length}
            </span>
          )}
        </>
      )}
    </span>
  );
}
