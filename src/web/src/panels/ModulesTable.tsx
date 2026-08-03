import type { ModuleManifest } from "../api/types";
import { td, th } from "../styles";

/** The original module list — the platform's independently-scalable modules and their ranges. */
export function ModulesTable({ modules }: { modules: ModuleManifest[] }) {
  if (modules.length === 0) {
    return <p style={{ color: "#5f6368" }}>No modules reported.</p>;
  }
  return (
    <table style={{ borderCollapse: "collapse", width: "100%" }}>
      <thead>
        <tr>
          <th style={th}>Module</th>
          <th style={th}>Kind</th>
          <th style={th}>Scale (min→max)</th>
          <th style={th}>Enabled</th>
        </tr>
      </thead>
      <tbody>
        {modules.map((m) => (
          <tr key={m.name}>
            <td style={td}>{m.displayName}</td>
            <td style={td}>{m.kind}</td>
            <td style={td}>
              {m.scaleProfile.minReplicas} → {m.scaleProfile.maxReplicas}
            </td>
            <td style={td}>{m.enabled ? "yes" : "no"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
