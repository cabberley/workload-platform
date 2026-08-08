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

/**
 * Read model for one published pack version — mirrors the API app's `PackRegistryEntryView`
 * (issue #57), the keyless/PII-free projection of a `packs_engine.registry.RegistryEntry`. Every
 * field is REQUIRED (always serialized). `digest` is the content-address / version identity (a
 * lowercase sha256 hex — NOT a secret); `signed` reflects whether the entry carries a well-formed
 * detached signature. The SPA only ever *reads* this shape. The raw key id / signature bytes are
 * intentionally NOT part of this contract (never egressed by the backend).
 */
export type PackRegistryEntry = {
  id: string;
  version: string;
  type: PackType;
  digest: string;
  createdAt: string;
  signed: boolean;
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

/** Mirrors `contracts.WorkloadGraph`. The API's graph endpoint additionally returns an opaque
 *  server-computed `graphRevision` over the FULL topology (nodes + edges) — optional so this stays
 *  back-compatible with the pure contract shape. The web treats it as an OPAQUE string (never
 *  hashes the graph itself). */
export type WorkloadGraph = {
  nodes: ResourceNode[];
  edges: DependencyEdge[];
  graphRevision?: string;
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
 * is an ISO-8601 datetime string. `provenance` is the explicit pack-vs-structural attribution
 * marker (issue #83): a `pack` finding carries `packId`+`packVersion`; a `structural` finding names
 * a `structuralKind` and has null pack id/version.
 */
export type ProvenanceKind = "pack" | "structural";
export type StructuralFindingKind = "spof";

export type Finding = {
  id: string;
  module: string;
  title: string;
  passed: boolean | null;
  severity: Severity;
  nodeId: string | null;
  blastRadius: number;
  evidence: SourceReference[];
  provenance: ProvenanceKind;
  packId: string | null;
  packVersion: string | null;
  structuralKind: StructuralFindingKind | null;
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

/**
/**
 * Mirrors `contracts.PackAssignment` (issue #37). Which pack version a workload is pinned to.
 * `assignedAt` is an ISO-8601 datetime string. The SPA only ever *reads* this shape — all
 * assignment writes go through the API (single writer).
 */
export type PackAssignment = {
  workload: string;
  packId: string;
  version: string;
  assignedBy: string;
  assignedAt: string;
};

/**
 * Mirrors the API app's `ImpactResult` read model (issue #56) — the projection of the CANONICAL
 * server-side `shared.blast_radius.compute_impact`. `states` maps every node id to its simulated
 * `HealthState` when `failedNode` is down; `blastRadius === down.length`. This is a *read* shape
 * only (the SPA never posts an impact). Do not add fields the backend does not send.
 */
export type ImpactResult = {
  failedNode: string;
  states: Record<string, HealthState>;
  blastRadius: number;
  down: string[];
  degraded: string[];
  /** Opaque server-computed revision of the topology the impact was computed on. Compare (as a
   *  string) with the displayed graph's `graphRevision` to detect edge-level staleness. */
  graphRevision: string;
};

/**
 * Mirrors `contracts.AgentResponse` — the console-facing analytical output of an auto-RCA
 * (`modules.aiops.rca`). Every field is REQUIRED (always serialized). `sourceReferences` is the
 * already-cited evidence the grounded explanation is constrained to. The SPA only ever *reads* this
 * shape; it never produces or mutates an RCA.
 */
export type AgentResponse = {
  agentName: string;
  taskType: string;
  inputSummary: string;
  findings: string[];
  risks: string[];
  recommendations: string[];
  sourceReferences: SourceReference[];
  confidence: number;
  nextActions: string[];
  generatedAt: string;
};

/**
 * One grounded, advisory RCA explanation entry — mirrors the `{ "advisory": string }` shape the
 * aiops module attaches at `ModuleRunResult.extra["rcaExplanation"]` (issue #54), index-aligned
 * with `extra["rca"]` (the `AgentResponse[]`). An EMPTY `advisory` means the keyless in-boundary
 * edge was UNCONFIGURED / below the confidence floor / ungrounded — the pure RCA result stands and
 * the console renders nothing for that entry (fail-closed, advisory-only).
 */
export type RcaExplanationEntry = {
  advisory: string;
};

/**
 * The console read-projection pairing an RCA `AgentResponse` with its (optional) grounded advisory
 * explanation. Purely a UI join over the module run result's `extra.rca` + `extra.rcaExplanation`;
 * `advisory` is `null` when no grounded explanation is available (nothing is rendered then).
 */
export type RcaExplanationView = {
  rca: AgentResponse;
  advisory: string | null;
};

/**
 * Mirrors `contracts.RcaAdvisory` — the BOUNDED, PII-safe console read model served by
 * `GET /api/workloads/{workload}/rca-explanations` (issue #54). It is the persisted, grounded,
 * advisory-only RCA explanation projection (only grounded/non-empty advisories are ever persisted,
 * so the list is empty when nothing is available — fail-closed by absence). Every field is REQUIRED
 * (always serialized). `index` aligns with the run's RCA responses; `sourceReferences` is the
 * already-cited evidence the advisory is grounded on. The SPA only ever *reads* this shape.
 */
export type RcaAdvisory = {
  index: number;
  agentName: string;
  taskType: string;
  confidence: number;
  advisory: string;
  findings: string[];
  risks: string[];
  recommendations: string[];
  sourceReferences: SourceReference[];
  generatedAt: string;
};
