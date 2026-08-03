import type { Spof } from "../graph/health";
import { SEVERITY_COLOR, SPOF_BADGE } from "../graph/encodings";
import { td, th } from "../styles";

/** Side panel: single points of failure ranked by blast radius (highest first). */
export function SpofPanel({ spofs }: { spofs: Spof[] }) {
  return (
    <section aria-label="Single points of failure" style={{ minWidth: 280 }}>
      <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>
        {SPOF_BADGE.glyph} SPOFs by blast radius
      </h3>

      {spofs.length === 0 ? (
        <p style={{ color: "#137333", fontSize: 13 }}>
          ✓ No single points of failure reported for this workload.
        </p>
      ) : (
        <table style={{ borderCollapse: "collapse", width: "100%" }}>
          <thead>
            <tr>
              <th style={th}>#</th>
              <th style={th}>Node / title</th>
              <th style={{ ...th, textAlign: "right" }}>Blast radius</th>
              <th style={th}>Severity</th>
            </tr>
          </thead>
          <tbody>
            {spofs.map((s, i) => (
              <tr key={s.nodeId}>
                <td style={td}>{i + 1}</td>
                <td style={td}>
                  <div style={{ fontWeight: 600 }}>{s.title}</div>
                  <code style={{ fontSize: 11, color: "#5f6368" }}>{s.nodeId}</code>
                  {s.detail && (
                    <div style={{ fontSize: 12, color: "#5f6368", marginTop: 2 }}>{s.detail}</div>
                  )}
                </td>
                <td style={{ ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
                  <strong>{s.blastRadius}</strong>
                </td>
                <td style={td}>
                  <span
                    style={{
                      display: "inline-block",
                      border: `1px solid ${SEVERITY_COLOR[s.severity]}`,
                      color: SEVERITY_COLOR[s.severity],
                      borderRadius: 4,
                      padding: "1px 6px",
                      fontSize: 11,
                      fontWeight: 700,
                      textTransform: "uppercase",
                    }}
                  >
                    {s.severity}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
