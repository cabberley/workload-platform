import type { HealthState, ResourceNode, WorkloadGraph } from "../api/types";
import type { NodeHealth, Spof } from "./health";
import { maxBlastRadius } from "./health";
import { computeLayout, DEFAULT_LAYOUT, type PositionedNode } from "./layout";
import {
  EDGE_ENCODING,
  healthEncoding,
  SPOF_BADGE,
  spofSizeScale,
  spofStrokeWidth,
} from "./encodings";
import { shapePath } from "./shapes";

type GraphViewProps = {
  graph: WorkloadGraph;
  health: Map<string, NodeHealth>;
  spofs: Map<string, Spof>;
};

const primaryLabel = (node: ResourceNode): string =>
  node.role ?? node.tier ?? node.name ?? node.id;

/** Renders the dependency graph as an accessible SVG (shape + glyph + label, never colour alone). */
export function GraphView({ graph, health, spofs }: GraphViewProps) {
  const maxBr = maxBlastRadius([...spofs.values()]);

  const sizeOf = (node: ResourceNode) => {
    const spof = spofs.get(node.id);
    const scale = spof && maxBr > 0 ? spofSizeScale(spof.blastRadius / maxBr) : 1;
    return {
      width: DEFAULT_LAYOUT.nodeWidth * scale,
      height: DEFAULT_LAYOUT.nodeHeight * scale,
    };
  };

  const layout = computeLayout(graph, sizeOf);

  return (
    <svg
      role="img"
      aria-label={`Dependency graph: ${graph.nodes.length} nodes, ${graph.edges.length} edges`}
      viewBox={`0 0 ${layout.width} ${layout.height}`}
      width="100%"
      style={{ minWidth: layout.width, maxWidth: "100%", height: "auto", background: "#fff" }}
    >
      <defs>
        <marker
          id="arrow"
          viewBox="0 0 10 10"
          refX="9"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#5f6368" />
        </marker>
      </defs>

      {layout.edges.map(({ edge, x1, y1, x2, y2 }, i) => {
        const enc = edge.redundant ? EDGE_ENCODING.redundant : EDGE_ENCODING.nonRedundant;
        return (
          <line
            key={`e-${edge.source}-${edge.target}-${i}`}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
            stroke={enc.stroke}
            strokeWidth={enc.width}
            strokeDasharray={enc.dasharray}
            markerEnd="url(#arrow)"
          >
            <title>
              {`${edge.source} → ${edge.target} (${edge.type}, ${enc.label})`}
            </title>
          </line>
        );
      })}

      {layout.nodes.map((pn) => (
        <GraphNode
          key={pn.node.id}
          positioned={pn}
          health={health.get(pn.node.id)?.state ?? "unknown"}
          spof={spofs.get(pn.node.id)}
          maxBr={maxBr}
        />
      ))}
    </svg>
  );
}

type GraphNodeProps = {
  positioned: PositionedNode;
  health: HealthState;
  spof: Spof | undefined;
  maxBr: number;
};

function GraphNode({ positioned, health, spof, maxBr }: GraphNodeProps) {
  const { node, x, y, width, height } = positioned;
  const enc = healthEncoding(health);
  const ratio = spof && maxBr > 0 ? spof.blastRadius / maxBr : 0;
  const strokeWidth = spof ? spofStrokeWidth(ratio) : enc.strokeWidth;

  const title =
    `${primaryLabel(node)} — ${node.type}\n` +
    `health: ${enc.label}` +
    (spof ? `\nSPOF · blast radius ${spof.blastRadius} · ${spof.severity}` : "");

  return (
    <g>
      <title>{title}</title>
      <path
        d={shapePath(enc.shape, x, y, width, height)}
        fill={enc.fill}
        stroke={spof ? SPOF_BADGE.color : enc.stroke}
        strokeWidth={strokeWidth}
        strokeDasharray={spof ? undefined : enc.strokeDasharray}
      />
      <text
        x={x + width / 2}
        y={y + 22}
        textAnchor="middle"
        style={{ font: "600 13px system-ui, sans-serif", fill: "#202124" }}
      >
        {truncate(primaryLabel(node), 20)}
      </text>
      <text
        x={x + width / 2}
        y={y + 38}
        textAnchor="middle"
        style={{ font: "11px system-ui, sans-serif", fill: "#5f6368" }}
      >
        {truncate(node.type, 24)}
      </text>
      <text
        x={x + width / 2}
        y={y + 54}
        textAnchor="middle"
        style={{ font: "600 11px system-ui, sans-serif", fill: enc.stroke }}
      >
        {`${enc.glyph} ${enc.label}`}
      </text>

      {spof && (
        <>
          {/* SPOF badge: shape + glyph + text, top-right — independent of colour. */}
          <rect
            x={x + width - 62}
            y={y - 12}
            width={58}
            height={20}
            rx={4}
            fill={SPOF_BADGE.color}
          />
          <text
            x={x + width - 33}
            y={y + 2}
            textAnchor="middle"
            style={{ font: "700 11px system-ui, sans-serif", fill: "#fff" }}
          >
            {`${SPOF_BADGE.glyph} ${SPOF_BADGE.label}`}
          </text>
          <text
            x={x + width / 2}
            y={y + height + 14}
            textAnchor="middle"
            style={{ font: "700 11px system-ui, sans-serif", fill: SPOF_BADGE.color }}
          >
            {`blast radius: ${spof.blastRadius}`}
          </text>
        </>
      )}
    </g>
  );
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
