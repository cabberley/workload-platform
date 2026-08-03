import type { AsyncState } from "../hooks/useAsync";

type WorkloadSelectorProps = {
  state: AsyncState<string[]>;
  selected: string | null;
  onSelect: (workload: string) => void;
};

/** Populated from `GET /api/workloads`; handles loading / error / empty gracefully. */
export function WorkloadSelector({ state, selected, onSelect }: WorkloadSelectorProps) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
      <label htmlFor="workload-select" style={{ fontWeight: 600 }}>
        Workload
      </label>

      {state.status === "loading" && <span style={{ color: "#5f6368" }}>Loading workloads…</span>}

      {state.status === "error" && (
        <span style={{ color: "crimson" }}>
          Could not load workloads ({state.error.message}).
        </span>
      )}

      {state.status === "success" && state.data.length === 0 && (
        <span style={{ color: "#5f6368" }}>
          No workloads discovered yet. Run discovery to populate the estate.
        </span>
      )}

      {state.status === "success" && state.data.length > 0 && (
        <select
          id="workload-select"
          value={selected ?? ""}
          onChange={(e) => onSelect(e.target.value)}
          style={{ padding: "6px 10px", fontSize: 14, borderRadius: 6, border: "1px solid #ccc" }}
        >
          <option value="" disabled>
            Select a workload…
          </option>
          {state.data.map((w) => (
            <option key={w} value={w}>
              {w}
            </option>
          ))}
        </select>
      )}
    </div>
  );
}
