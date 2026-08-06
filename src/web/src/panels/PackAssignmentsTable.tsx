import type { PackAssignment } from "../api/types";
import { td, th } from "../styles";

/**
 * Read-only view of pack-version assignments (issue #37): which pack version each workload is
 * pinned to, and who assigned it when (provenance). Populated from `GET /api/pack-assignments`.
 * The console never assigns — all assignment writes go through the API (single writer).
 */
export function PackAssignmentsTable({ assignments }: { assignments: PackAssignment[] }) {
  if (assignments.length === 0) {
    return (
      <p style={{ color: "#5f6368" }}>
        No pack assignments yet. Import a signed pack and assign a version via the API.
      </p>
    );
  }
  return (
    <table style={{ borderCollapse: "collapse", width: "100%" }}>
      <thead>
        <tr>
          <th style={th}>Workload</th>
          <th style={th}>Pack</th>
          <th style={th}>Version</th>
          <th style={th}>Assigned by</th>
          <th style={th}>Assigned at</th>
        </tr>
      </thead>
      <tbody>
        {assignments.map((a) => (
          <tr key={`${a.workload}::${a.packId}`}>
            <td style={td}>{a.workload}</td>
            <td style={td}>{a.packId}</td>
            <td style={td}>{a.version}</td>
            <td style={td}>{a.assignedBy}</td>
            <td style={td}>{new Date(a.assignedAt).toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
