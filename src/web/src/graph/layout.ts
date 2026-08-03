// Pure, deterministic layered graph layout — no dependencies, no I/O. Produces SVG coordinates
// for nodes and edge endpoints so the view can render a legible left-to-right dependency flow.

import type { DependencyEdge, ResourceNode, WorkloadGraph } from "../api/types";

export type LayoutOptions = {
  columnGap: number;
  rowGap: number;
  marginX: number;
  marginY: number;
  nodeWidth: number;
  nodeHeight: number;
};

export const DEFAULT_LAYOUT: LayoutOptions = {
  columnGap: 240,
  rowGap: 120,
  marginX: 48,
  marginY: 48,
  nodeWidth: 168,
  nodeHeight: 64,
};

export type PositionedNode = {
  node: ResourceNode;
  x: number; // top-left
  y: number;
  width: number;
  height: number;
  cx: number; // centre
  cy: number;
  layer: number;
};

export type RoutedEdge = {
  edge: DependencyEdge;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
};

export type Layout = {
  nodes: PositionedNode[];
  edges: RoutedEdge[];
  width: number;
  height: number;
};

/**
 * Group nodes into strongly connected components (Tarjan, iterative to avoid recursion limits).
 * Returns each node's SCC id and the total SCC count. Deterministic: nodes are visited in input
 * order and neighbours in edge order. Self-loops and disconnected nodes are handled (a lone node
 * is its own SCC). Iterative so very large graphs cannot overflow the call stack.
 */
function stronglyConnectedComponents(
  nodeIds: string[],
  adj: Map<string, string[]>,
): { sccOf: Map<string, number>; count: number } {
  const index = new Map<string, number>();
  const low = new Map<string, number>();
  const onStack = new Set<string>();
  const tarjanStack: string[] = [];
  const sccOf = new Map<string, number>();
  let counter = 0;
  let sccCount = 0;

  for (const start of nodeIds) {
    if (index.has(start)) continue;
    // Explicit work stack of DFS frames: `v` = node, `i` = next neighbour to explore.
    const work: Array<{ v: string; i: number }> = [{ v: start, i: 0 }];
    while (work.length > 0) {
      const frame = work[work.length - 1];
      const v = frame.v;
      if (frame.i === 0) {
        index.set(v, counter);
        low.set(v, counter);
        counter += 1;
        tarjanStack.push(v);
        onStack.add(v);
      }
      const neighbours = adj.get(v) ?? [];
      let descended = false;
      while (frame.i < neighbours.length) {
        const w = neighbours[frame.i];
        frame.i += 1;
        if (!index.has(w)) {
          work.push({ v: w, i: 0 }); // descend into w
          descended = true;
          break;
        }
        if (onStack.has(w)) {
          low.set(v, Math.min(low.get(v)!, index.get(w)!));
        }
      }
      if (descended) continue;

      if (low.get(v) === index.get(v)) {
        // v is an SCC root — pop the component off the Tarjan stack.
        let w: string;
        do {
          w = tarjanStack.pop()!;
          onStack.delete(w);
          sccOf.set(w, sccCount);
        } while (w !== v);
        sccCount += 1;
      }
      work.pop();
      if (work.length > 0) {
        const parent = work[work.length - 1].v;
        low.set(parent, Math.min(low.get(parent)!, low.get(v)!));
      }
    }
  }
  return { sccOf, count: sccCount };
}

/**
 * Assign each node to a finite layer (column). An edge `source → target` means source depends on
 * target, so the target sits one layer deeper (further right).
 *
 * Cycles (redundant back-edges, rings) are handled by collapsing each strongly connected component
 * into a single super-node to form the condensation DAG, then longest-path layering that DAG; every
 * member of an SCC shares its component's layer. This guarantees:
 *   (a) every node gets exactly one layer;
 *   (b) `layer <= sccCount - 1 <= nodes.length - 1` — a DAG's longest chain of distinct SCCs has at
 *       most `sccCount` vertices, hence at most `sccCount - 1` edges, so no layer can exceed the
 *       node count (a 10-node ring is ONE SCC → layer 0, not 100);
 *   (c) all layers are finite integers → no NaN/Infinity coordinates downstream;
 *   (d) self-loops and disconnected components are absorbed as their own SCCs.
 */
function computeLayers(nodes: ResourceNode[], edges: DependencyEdge[]): Map<string, number> {
  const nodeIds = nodes.map((n) => n.id);
  const present = new Set(nodeIds);

  const adj = new Map<string, string[]>();
  for (const id of nodeIds) adj.set(id, []);
  for (const e of edges) {
    if (present.has(e.source) && present.has(e.target)) adj.get(e.source)!.push(e.target);
  }

  const { sccOf, count } = stronglyConnectedComponents(nodeIds, adj);

  // Condensation edges between DISTINCT components (self-loops within an SCC are dropped).
  const condensation: Array<[number, number]> = [];
  for (const e of edges) {
    const from = sccOf.get(e.source);
    const to = sccOf.get(e.target);
    if (from === undefined || to === undefined || from === to) continue;
    condensation.push([from, to]);
  }

  // Longest-path layering on the condensation DAG. Because it is acyclic, relaxation converges in
  // at most `count` passes and the max layer is bounded by `count - 1` (proof in the doc comment).
  const sccLayer = new Array<number>(count).fill(0);
  for (let pass = 0; pass < count; pass += 1) {
    let changed = false;
    for (const [from, to] of condensation) {
      if (sccLayer[to] < sccLayer[from] + 1) {
        sccLayer[to] = sccLayer[from] + 1;
        changed = true;
      }
    }
    if (!changed) break;
  }

  const depth = new Map<string, number>();
  for (const id of nodeIds) depth.set(id, sccLayer[sccOf.get(id)!] ?? 0);
  return depth;
}

/**
 * Lay out the graph into columns by dependency depth, distributing nodes vertically within each
 * column. `sizeOf` lets callers enlarge SPOF nodes; the layout still reserves even row slots so
 * enlarged nodes stay centred and non-overlapping.
 */
export function computeLayout(
  graph: WorkloadGraph,
  sizeOf: (node: ResourceNode) => { width: number; height: number },
  opts: LayoutOptions = DEFAULT_LAYOUT,
): Layout {
  const depth = computeLayers(graph.nodes, graph.edges);

  const columns = new Map<number, ResourceNode[]>();
  for (const node of graph.nodes) {
    const layer = depth.get(node.id) ?? 0;
    const col = columns.get(layer) ?? [];
    col.push(node);
    columns.set(layer, col);
  }
  // Stable ordering within a column: by tier, then role/name, so re-renders don't jump around.
  for (const col of columns.values()) {
    col.sort(
      (a, b) =>
        (a.tier ?? "").localeCompare(b.tier ?? "") ||
        (a.role ?? a.name).localeCompare(b.role ?? b.name),
    );
  }

  const positioned = new Map<string, PositionedNode>();
  const maxRows = Math.max(1, ...[...columns.values()].map((c) => c.length));

  for (const [layer, col] of columns) {
    // Vertically centre shorter columns against the tallest one.
    const offset = ((maxRows - col.length) * opts.rowGap) / 2;
    col.forEach((node, row) => {
      const size = sizeOf(node);
      const slotCy = opts.marginY + offset + row * opts.rowGap + opts.nodeHeight / 2;
      const cx = opts.marginX + layer * opts.columnGap + opts.nodeWidth / 2;
      positioned.set(node.id, {
        node,
        x: cx - size.width / 2,
        y: slotCy - size.height / 2,
        width: size.width,
        height: size.height,
        cx,
        cy: slotCy,
        layer,
      });
    });
  }

  const routed: RoutedEdge[] = [];
  for (const edge of graph.edges) {
    const s = positioned.get(edge.source);
    const t = positioned.get(edge.target);
    if (!s || !t) continue; // edge references a node outside the graph — skip defensively
    routed.push({ edge, x1: s.cx, y1: s.cy, x2: t.cx, y2: t.cy });
  }

  const maxLayer = Math.max(0, ...[...columns.keys()]);
  const width = opts.marginX * 2 + maxLayer * opts.columnGap + opts.nodeWidth;
  const height = opts.marginY * 2 + (maxRows - 1) * opts.rowGap + opts.nodeHeight;

  // Dev-only sanity check (stripped from production builds): the SCC condensation guarantees every
  // layer is finite and bounded by the node count, so dimensions can never explode on cyclic graphs.
  if (typeof import.meta.env !== "undefined" && import.meta.env.DEV) {
    const n = graph.nodes.length;
    const bad = [...positioned.values()].find(
      (p) => !Number.isFinite(p.cx) || !Number.isFinite(p.cy) || p.layer < 0 || p.layer > n,
    );
    if (bad) {
      // eslint-disable-next-line no-console
      console.warn("computeLayout: layer/coordinate bound violated", bad.node.id, bad.layer, n);
    }
  }

  return { nodes: [...positioned.values()], edges: routed, width, height };
}
