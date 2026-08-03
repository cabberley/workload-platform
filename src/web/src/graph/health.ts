// Pure derivation logic (no I/O) — mirrors the platform rule that scoring/blast-radius math are
// pure functions. We do NOT recompute blast radius here: the numbers come straight from the
// dependency_graph module's findings. This module only *ranks* and *maps status*.

import type { Finding, HealthState, ResourceNode, Severity } from "../api/types";

const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER[severity] ?? 0;
}

/** A node's derived health plus the failing findings that explain it. */
export type NodeHealth = {
  state: HealthState;
  worstSeverity: Severity | null;
  failing: Finding[];
};

/** A failing finding counts fail-closed: only `passed === false` is a failure (unknown ≠ down). */
function isFailure(finding: Finding): boolean {
  return finding.passed === false;
}

/**
 * Map worst failing severity to a health state:
 *  - critical/high  → down
 *  - medium/low     → degraded
 *  - no failure     → up
 * A node with only unknown/passing findings is `up`.
 */
function stateForSeverity(worst: Severity | null): HealthState {
  if (worst === null) return "up";
  const rank = severityRank(worst);
  if (rank >= severityRank("high")) return "down";
  return "degraded";
}

/**
 * Derive per-node health from ALL findings for the workload. A node referenced (via `nodeId`) by
 * a failing finding takes the worst severity among those findings.
 */
export function deriveHealth(
  nodes: ResourceNode[],
  findings: Finding[],
): Map<string, NodeHealth> {
  const byNode = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.nodeId || !isFailure(f)) continue;
    const list = byNode.get(f.nodeId) ?? [];
    list.push(f);
    byNode.set(f.nodeId, list);
  }

  const health = new Map<string, NodeHealth>();
  for (const node of nodes) {
    const failing = byNode.get(node.id) ?? [];
    let worst: Severity | null = null;
    for (const f of failing) {
      if (worst === null || severityRank(f.severity) > severityRank(worst)) {
        worst = f.severity;
      }
    }
    health.set(node.id, { state: stateForSeverity(worst), worstSeverity: worst, failing });
  }
  return health;
}

/** A single point of failure, ranked from a dependency_graph finding. */
export type Spof = {
  nodeId: string;
  title: string;
  blastRadius: number;
  severity: Severity;
  detail: string | null;
};

/**
 * Rank single points of failure by blast radius (highest first). Input is the set of
 * dependency_graph findings; we keep failing findings that name a node and carry a blast radius.
 * Ties break on severity then nodeId for a stable order.
 */
export function rankSpofs(dependencyFindings: Finding[]): Spof[] {
  return dependencyFindings
    .filter((f): f is Finding & { nodeId: string } => isFailure(f) && !!f.nodeId)
    .map((f) => ({
      nodeId: f.nodeId,
      title: f.title,
      blastRadius: f.blastRadius,
      severity: f.severity,
      detail: f.detail ?? null,
    }))
    .sort(
      (a, b) =>
        b.blastRadius - a.blastRadius ||
        severityRank(b.severity) - severityRank(a.severity) ||
        a.nodeId.localeCompare(b.nodeId),
    );
}

/** Max blast radius across SPOFs — used to normalise node sizing/border weight in the graph. */
export function maxBlastRadius(spofs: Spof[]): number {
  return spofs.reduce((max, s) => Math.max(max, s.blastRadius), 0);
}
