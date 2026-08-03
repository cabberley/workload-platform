// Clearly-fake synthetic fixtures for web component tests. NO real customer data / PHI / PII —
// every id, name and value here is invented for testing only.
import type { DriftReport, Finding, WorkloadGraph } from "../api/types";

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-fake-1",
    module: "quality_checks",
    title: "TLS enforced on public endpoint",
    passed: true,
    severity: "medium",
    nodeId: "node-fake-web",
    blastRadius: 3,
    evidence: [{ kind: "resource", id: "/fake/resource/id", detail: "synthetic evidence" }],
    packId: "rule.tls.fake",
    packVersion: "1.2.3",
    detail: "Synthetic detail for test.",
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

export function makeGraph(overrides: Partial<WorkloadGraph> = {}): WorkloadGraph {
  return {
    nodes: [
      { id: "n-web", name: "web", type: "app", workload: "atlas", tier: "web", role: "frontend", tags: {} },
      { id: "n-api", name: "api", type: "app", workload: "atlas", tier: "app", role: "backend", tags: {} },
      { id: "n-db", name: "db", type: "sql", workload: "atlas", tier: "data", role: "database", tags: {} },
    ],
    edges: [
      { source: "n-web", target: "n-api", type: "depends_on", redundant: true, origin: "auto" },
      { source: "n-api", target: "n-db", type: "depends_on", redundant: false, origin: "auto" },
    ],
    graphRevision: "rev-fake-1",
    ...overrides,
  };
}

export function makeDrift(overrides: Partial<DriftReport> = {}): DriftReport {
  return {
    workload: "atlas",
    newFailures: [],
    recovered: [],
    stillFailing: [],
    addedNodes: [],
    removedNodes: [],
    ...overrides,
  };
}
