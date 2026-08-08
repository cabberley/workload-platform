// Clearly-fake synthetic fixtures for web component tests. NO real customer data / PHI / PII —
// every id, name and value here is invented for testing only.
import type { AgentResponse, DriftReport, Finding, ModuleManifest, PackRegistryEntry, RcaAdvisory, WorkloadGraph } from "../api/types";

export function makeModule(overrides: Partial<ModuleManifest> = {}): ModuleManifest {
  return {
    name: "discovery",
    displayName: "Discovery",
    kind: "service",
    enabled: true,
    consumes: ["workload"],
    produces: ["estate"],
    scaleProfile: {
      kind: "service",
      minReplicas: 1,
      maxReplicas: 3,
      triggers: [],
      cpu: 0.5,
      memoryGi: 1,
    },
    ...overrides,
  };
}

export function makePack(overrides: Partial<PackRegistryEntry> = {}): PackRegistryEntry {
  return {
    id: "rule.tls.fake",
    version: "1.2.0",
    type: "rule",
    digest: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    createdAt: "2026-01-01T00:00:00Z",
    signed: true,
    ...overrides,
  };
}

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
    provenance: "pack",
    packId: "rule.tls.fake",
    packVersion: "1.2.3",
    structuralKind: null,
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

export function makeAgentResponse(overrides: Partial<AgentResponse> = {}): AgentResponse {
  return {
    agentName: "aiops",
    taskType: "auto-rca",
    inputSummary: "synthetic input summary",
    findings: ["node-fake-01 shows cpu_saturation_ratio above threshold"],
    risks: ["availability degraded for the widget workload"],
    recommendations: ["investigate the cited node"],
    sourceReferences: [
      { kind: "resource", id: "/fake/resource/widget-01", detail: "observed" },
      { kind: "metric", id: "cpu_saturation_ratio", detail: null },
    ],
    confidence: 0.9,
    nextActions: ["auto-rca"],
    generatedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

export function makeRcaAdvisory(overrides: Partial<RcaAdvisory> = {}): RcaAdvisory {
  return {
    index: 0,
    agentName: "aiops.autorca",
    taskType: "root_cause_analysis",
    confidence: 0.9,
    advisory: "The evidence indicates node-fake-01 is saturated.",
    findings: ["node-fake-01 shows cpu_saturation_ratio above threshold"],
    risks: ["availability degraded for the widget workload"],
    recommendations: ["investigate the cited node"],
    sourceReferences: [
      { kind: "resource", id: "/fake/resource/widget-01", detail: "observed" },
      { kind: "metric", id: "cpu_saturation_ratio", detail: null },
    ],
    generatedAt: "2026-01-01T00:00:00Z",
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
