// TypeScript mirrors of the shared Pydantic contracts in `src/shared/contracts.py`.
// Keep these field names/casing in lock-step with the Python source of truth — do not invent
// fields. The SPA only ever *reads* these shapes.
//
// Serialization rule (verified against `src/shared/contracts.py`): Pydantic includes EVERY field
// in JSON output (defaults and `None` are emitted, not dropped). So each read-model field below is
// REQUIRED (always present). Fields typed `X | None` in Python are `T | null` here (present but
// nullable) — NOT `?:` optional. `?:` is reserved for fields the API genuinely omits (none today).

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Derived-in-UI node status; not a wire field. */
export type HealthState = "up" | "degraded" | "down" | "unknown";

/** Mirrors `contracts.ModuleKind`. */
export type ModuleKind = "service" | "job";

/** Mirrors `contracts.PackType`. */
export type PackType = "workload" | "rule" | "telemetry" | "dependency" | "ops";

/** Mirrors `contracts.ScaleTrigger`. */
export type ScaleTrigger = {
  type: string;
  metadata: Record<string, string>;
};

/** Mirrors `contracts.ScaleProfile`. */
export type ScaleProfile = {
  kind: ModuleKind;
  minReplicas: number;
  maxReplicas: number;
  triggers: ScaleTrigger[];
  cpu: number;
  memoryGi: number;
};

/** Mirrors `contracts.ModuleManifest`. */
export type ModuleManifest = {
  name: string;
  displayName: string;
  kind: ModuleKind;
  enabled: boolean;
  consumes: PackType[];
  produces: string[];
  scaleProfile: ScaleProfile;
};

/** Mirrors `contracts.ResourceNode`. `workload`/`tier`/`role` are nullable-but-present. */
export type ResourceNode = {
  id: string;
  name: string;
  type: string;
  workload: string | null;
  tier: string | null;
  role: string | null;
  tags: Record<string, string>;
};

/** Mirrors `contracts.EdgeType`. */
export type EdgeType = "depends_on" | "load_balances" | "replicates_to" | "routes_to";

/** Mirrors `contracts.DependencyEdge`. `origin` is always serialized (defaults to "auto"). */
export type DependencyEdge = {
  source: string;
  target: string;
  type: EdgeType;
  redundant: boolean;
  origin: string;
};

/** Mirrors `contracts.WorkloadGraph`. */
export type WorkloadGraph = {
  nodes: ResourceNode[];
  edges: DependencyEdge[];
};

/** Mirrors `contracts.SourceReference`. `detail` is nullable-but-present. */
export type SourceReference = {
  kind: string;
  id: string;
  detail: string | null;
};

/**
 * Mirrors `contracts.Finding`. `passed` is tri-state (`null` = unknown, treated as NOT a failure —
 * fail-closed). `nodeId`, `packId`, `packVersion`, `detail` are nullable-but-present; `createdAt`
 * is an ISO-8601 datetime string.
 */
export type Finding = {
  id: string;
  module: string;
  title: string;
  passed: boolean | null;
  severity: Severity;
  nodeId: string | null;
  blastRadius: number;
  evidence: SourceReference[];
  packId: string | null;
  packVersion: string | null;
  detail: string | null;
  createdAt: string;
};

/** Mirrors `contracts.DriftReport` (the subset the drift badge renders). */
export type DriftReport = {
  workload: string;
  newFailures: Finding[];
  recovered: Finding[];
  stillFailing: Finding[];
  addedNodes: string[];
  removedNodes: string[];
};
