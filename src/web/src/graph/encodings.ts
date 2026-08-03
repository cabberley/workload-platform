// Central definition of every visual encoding used by the graph + legend. Accessibility rule
// (Definition of Done): colour is NEVER the only signal. Each health state also has a distinct
// SHAPE, a GLYPH, a TEXT LABEL, and a border style; SPOFs add a badge, size and border weight.
// Legend and GraphView both import from here so the legend can never drift from the rendering.

import type { HealthState, Severity } from "../api/types";

export type NodeShape = "roundedRect" | "hexagon" | "octagon";

export type HealthEncoding = {
  label: string;
  glyph: string; // non-colour cue rendered in the node + legend
  fill: string;
  stroke: string;
  strokeWidth: number;
  strokeDasharray?: string;
  shape: NodeShape;
  description: string;
};

/** Health → full visual encoding. Shape + glyph + label make each state colour-independent. */
export const HEALTH_ENCODING: Record<Exclude<HealthState, "unknown"> | "unknown", HealthEncoding> = {
  up: {
    label: "UP",
    glyph: "●",
    fill: "#e6f4ea",
    stroke: "#137333",
    strokeWidth: 1.5,
    shape: "roundedRect",
    description: "Healthy — no failing findings reference this node.",
  },
  degraded: {
    label: "DEGRADED",
    glyph: "▲",
    fill: "#fef7e0",
    stroke: "#b06000",
    strokeWidth: 2,
    strokeDasharray: "6 4",
    shape: "hexagon",
    description: "A medium/low-severity finding references this node.",
  },
  down: {
    label: "DOWN",
    glyph: "■",
    fill: "#fce8e6",
    stroke: "#a50e0e",
    strokeWidth: 3,
    shape: "octagon",
    description: "A high/critical-severity finding references this node.",
  },
  unknown: {
    label: "UNKNOWN",
    glyph: "◇",
    fill: "#f1f3f4",
    stroke: "#5f6368",
    strokeWidth: 1.5,
    strokeDasharray: "2 3",
    shape: "roundedRect",
    description: "No health signal for this node.",
  },
};

export function healthEncoding(state: HealthState): HealthEncoding {
  return HEALTH_ENCODING[state];
}

/** Severity → a small colour + word chip (word makes it colour-independent). */
export const SEVERITY_COLOR: Record<Severity, string> = {
  info: "#5f6368",
  low: "#1a73e8",
  medium: "#b06000",
  high: "#c5221f",
  critical: "#a50e0e",
};

/** SPOF badge — a shape+text cue independent of colour, shown on flagged nodes and in the legend. */
export const SPOF_BADGE = { glyph: "⚠", label: "SPOF", color: "#a50e0e" } as const;

/**
 * Simulated-failure origin badge — marks the node the user chose to "fail" in a blast-radius
 * simulation (issue #56). Distinct glyph + word + colour so a simulated origin never reads as a
 * live-health `down`, and the recolored graph never masquerades as live health.
 */
export const SIM_BADGE = { glyph: "⌁", label: "SIMULATED FAILURE", color: "#6a1b9a" } as const;

/** Edge styling — solid = redundant (has a backup path), dashed = non-redundant (single path). */
export const EDGE_ENCODING = {
  redundant: {
    label: "redundant (has backup)",
    dasharray: undefined as string | undefined,
    stroke: "#5f6368",
    width: 1.5,
  },
  nonRedundant: {
    label: "non-redundant (single path)",
    dasharray: "7 5",
    stroke: "#a50e0e",
    width: 1.75,
  },
} as const;

/**
 * Border weight grows with blast radius (1 → thin, max → thick). This is a non-colour size cue
 * for how much fails if the node fails; `ratio` is blastRadius / maxBlastRadius in [0, 1].
 */
export function spofStrokeWidth(ratio: number): number {
  return 3 + Math.round(ratio * 5); // 3px .. 8px
}

/** Node size scales with blast radius so bigger blast = bigger node (non-colour cue). */
export function spofSizeScale(ratio: number): number {
  return 1 + ratio * 0.6; // up to 1.6x
}
