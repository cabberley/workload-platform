import { describe, it, expect } from "vitest";
import { summariseGraph } from "./estate";
import { makeGraph } from "../test/fixtures";

describe("summariseGraph (pure)", () => {
  it("counts nodes/edges and collects tiers/roles", () => {
    const s = summariseGraph(makeGraph());
    expect(s.nodeCount).toBe(3);
    expect(s.edgeCount).toBe(2);
    expect(s.tiers).toEqual(["app", "data", "web"]);
    expect(s.roles).toEqual(["backend", "database", "frontend"]);
  });

  it("counts non-redundant (single-path) edges as a factual property", () => {
    const s = summariseGraph(makeGraph());
    expect(s.singlePathEdges).toBe(1);
  });

  it("derives most depended-on by NON-REDUNDANT in-degree", () => {
    // Fixture default: only n-api->n-db is non-redundant, so n-db has non-redundant in-degree 1.
    const s = summariseGraph(makeGraph());
    expect(s.mostDependedOn).toEqual({ nodeId: "n-db", name: "db", inDegree: 1 });
  });

  it("does NOT surface a node reached only via redundant edges (no risk implication)", () => {
    const graph = makeGraph({
      edges: [
        { source: "n-web", target: "n-db", type: "depends_on", redundant: true, origin: "auto" },
        { source: "n-api", target: "n-db", type: "depends_on", redundant: true, origin: "auto" },
      ],
    });
    const s = summariseGraph(graph);
    // Both dependents have a backup path → n-db is not presented as depended-on.
    expect(s.mostDependedOn).toBeNull();
    expect(s.singlePathEdges).toBe(0);
  });

  it("ranks by non-redundant in-degree when several nodes are depended-on", () => {
    const graph = makeGraph({
      edges: [
        { source: "n-web", target: "n-db", type: "depends_on", redundant: false, origin: "auto" },
        { source: "n-api", target: "n-db", type: "depends_on", redundant: false, origin: "auto" },
        { source: "n-web", target: "n-api", type: "depends_on", redundant: false, origin: "auto" },
      ],
    });
    const s = summariseGraph(graph);
    expect(s.mostDependedOn).toEqual({ nodeId: "n-db", name: "db", inDegree: 2 });
    expect(s.singlePathEdges).toBe(3);
  });

  it("ignores null tier/role and returns null mostDependedOn with no edges", () => {
    const graph = makeGraph({
      nodes: [
        { id: "solo", name: "solo", type: "app", workload: "atlas", tier: null, role: null, tags: {} },
      ],
      edges: [],
    });
    const s = summariseGraph(graph);
    expect(s.tiers).toEqual([]);
    expect(s.roles).toEqual([]);
    expect(s.singlePathEdges).toBe(0);
    expect(s.mostDependedOn).toBeNull();
  });
});
