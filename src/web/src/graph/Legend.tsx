import type { CSSProperties } from "react";
import type { HealthState } from "../api/types";
import { EDGE_ENCODING, HEALTH_ENCODING, SPOF_BADGE } from "./encodings";
import { shapePath } from "./shapes";

const HEALTH_ORDER: HealthState[] = ["up", "degraded", "down", "unknown"];

/** Explains every visual encoding so the graph is legible without relying on colour. */
export function Legend() {
  return (
    <section aria-label="Graph legend" style={box}>
      <h3 style={heading}>Legend</h3>

      <div style={group}>
        <span style={groupTitle}>Node health (shape + glyph + label + colour)</span>
        <ul style={list}>
          {HEALTH_ORDER.map((state) => {
            const enc = HEALTH_ENCODING[state];
            return (
              <li key={state} style={item}>
                <svg width={34} height={26} aria-hidden="true">
                  <path
                    d={shapePath(enc.shape, 2, 2, 30, 22)}
                    fill={enc.fill}
                    stroke={enc.stroke}
                    strokeWidth={enc.strokeWidth}
                    strokeDasharray={enc.strokeDasharray}
                  />
                </svg>
                <span>
                  <strong>
                    {enc.glyph} {enc.label}
                  </strong>{" "}
                  — {enc.description}
                </span>
              </li>
            );
          })}
        </ul>
      </div>

      <div style={group}>
        <span style={groupTitle}>Single point of failure</span>
        <ul style={list}>
          <li style={item}>
            <span
              style={{
                display: "inline-block",
                background: SPOF_BADGE.color,
                color: "#fff",
                borderRadius: 4,
                padding: "1px 6px",
                font: "700 11px system-ui, sans-serif",
              }}
            >
              {SPOF_BADGE.glyph} {SPOF_BADGE.label}
            </span>
            <span>
              Badge + thicker border + larger node + a numeric <em>blast radius</em> label. Node
              size and border weight scale with blast radius (bigger = more nodes fail with it).
            </span>
          </li>
        </ul>
      </div>

      <div style={group}>
        <span style={groupTitle}>Edges (dependency direction →)</span>
        <ul style={list}>
          <li style={item}>
            <svg width={44} height={12} aria-hidden="true">
              <line
                x1={2}
                y1={6}
                x2={42}
                y2={6}
                stroke={EDGE_ENCODING.redundant.stroke}
                strokeWidth={EDGE_ENCODING.redundant.width}
              />
            </svg>
            <span>Solid — {EDGE_ENCODING.redundant.label}</span>
          </li>
          <li style={item}>
            <svg width={44} height={12} aria-hidden="true">
              <line
                x1={2}
                y1={6}
                x2={42}
                y2={6}
                stroke={EDGE_ENCODING.nonRedundant.stroke}
                strokeWidth={EDGE_ENCODING.nonRedundant.width}
                strokeDasharray={EDGE_ENCODING.nonRedundant.dasharray}
              />
            </svg>
            <span>Dashed — {EDGE_ENCODING.nonRedundant.label}</span>
          </li>
        </ul>
      </div>
    </section>
  );
}

const box: CSSProperties = {
  border: "1px solid #e0e0e0",
  borderRadius: 8,
  padding: 16,
  background: "#fafafa",
};
const heading: CSSProperties = { margin: "0 0 8px", fontSize: 15 };
const group: CSSProperties = { marginTop: 12 };
const groupTitle: CSSProperties = { fontWeight: 600, fontSize: 13, color: "#3c4043" };
const list: CSSProperties = { listStyle: "none", padding: 0, margin: "6px 0 0" };
const item: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  margin: "6px 0",
  fontSize: 13,
  lineHeight: 1.35,
};
