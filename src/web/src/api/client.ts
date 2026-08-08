// Read-only API client for the platform read models. Every call is a GET — the console never
// writes state (no POST/PUT/DELETE anywhere in the SPA). Requests hit the same origin: in dev the
// Vite server proxies `/api` to the FastAPI core (see `vite.config.ts`); in the deployed topology
// the web container's nginx reverse-proxies same-origin `/api/*` to the API's internal ingress
// (see `infra/docker/nginx.conf.template`), so the browser never contacts the internal API directly.

import type {
  DriftReport,
  Finding,
  ImpactResult,
  ModuleManifest,
  PackAssignment,
  PackRegistryEntry,
  RcaAdvisory,
  WorkloadGraph,
} from "./types";

/** Signals an HTTP error while preserving the status so callers can special-case 404. */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// Keyless bearer-token seam (issue #64). When Entra sign-in is wired (see `auth/AuthProvider`), the
// provider registers a getter that returns a FRESH access token (acquired silently from the MSAL
// cache) for the API audience; `getJson` attaches it as `Authorization: Bearer`. No token is stored
// in this module — it is fetched per request and never logged. When auth is not configured the
// provider stays `null` and requests go out unauthenticated (the documented local/no-auth path).
export type TokenProvider = () => Promise<string | null>;

let tokenProvider: TokenProvider | null = null;

/** Register (or clear, with `null`) the bearer-token provider used for every `/api/*` request. */
export function setAuthTokenProvider(provider: TokenProvider | null): void {
  tokenProvider = provider;
}

async function authHeaders(): Promise<Record<string, string>> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (tokenProvider !== null) {
    const token = await tokenProvider();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }
  return headers;
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { method: "GET", headers: await authHeaders(), signal });
  } catch (cause) {
    throw new ApiError(0, `network error: ${String(cause)}`);
  }
  if (!res.ok) {
    throw new ApiError(res.status, `${res.status} ${res.statusText}`.trim());
  }
  return (await res.json()) as T;
}

export function fetchModules(): Promise<ModuleManifest[]> {
  return getJson<ModuleManifest[]>("/api/modules");
}

/**
 * The pack-version registry catalogue (issue #57). Read-only: the backend returns `[]` (never an
 * error) when no registry is wired, so callers must treat an empty list as "no catalogue" — not as
 * an all-clear. Assigning a version to a workload is a *write* that must go through the (not-yet-
 * present) validated assignment backend — see `TODO(human)` in `PacksConsole`.
 */
export function fetchPacks(): Promise<PackRegistryEntry[]> {
  return getJson<PackRegistryEntry[]>("/api/packs");
}

export function fetchWorkloads(): Promise<string[]> {
  return getJson<string[]>("/api/workloads");
}

/** The dependency graph. The core returns 404 when no graph has been persisted yet. */
export function fetchGraph(workload: string): Promise<WorkloadGraph> {
  return getJson<WorkloadGraph>(`/api/workloads/${encodeURIComponent(workload)}/graph`);
}

/** Findings for a workload, optionally filtered to a single producing module. */
export function fetchFindings(workload: string, module?: string): Promise<Finding[]> {
  const suffix = module ? `?module=${encodeURIComponent(module)}` : "";
  return getJson<Finding[]>(`/api/workloads/${encodeURIComponent(workload)}/findings${suffix}`);
}

export function fetchDrift(workload: string): Promise<DriftReport> {
  return getJson<DriftReport>(`/api/workloads/${encodeURIComponent(workload)}/drift`);
}

/**
 * The persisted, grounded, advisory-only RCA explanations for a workload (issue #54). Read-only
 * in-boundary console path: the backend returns `[]` (never an error) when no grounded advisory is
 * available — an unconfigured/low-confidence/ungrounded run persists nothing, so an empty list is
 * "no advisory", NOT an all-clear. The advisory is never a remediation and is never applied.
 */
export function fetchRcaExplanations(workload: string): Promise<RcaAdvisory[]> {
  return getJson<RcaAdvisory[]>(
    `/api/workloads/${encodeURIComponent(workload)}/rca-explanations`,
  );
}

/**
 * Every pack-version assignment across all workloads (issue #37) — read-only visibility for both
 * Microsoft and the customer. The SPA never assigns; assignment writes go through the API (PUT).
 */
export function fetchPackAssignments(): Promise<PackAssignment[]> {
  return getJson<PackAssignment[]>("/api/pack-assignments");
}

/**
 * Canonical blast-radius impact of simulating `node`'s failure (issue #56). The core returns 404
 * when no graph is persisted OR when `node` is not in the graph (fail-closed) — callers surface
 * that, never a false all-clear. The math is server-side only; this just reads the projection.
 */
export function fetchImpact(
  workload: string,
  node: string,
  signal?: AbortSignal,
): Promise<ImpactResult> {
  return getJson<ImpactResult>(
    `/api/workloads/${encodeURIComponent(workload)}/impact?node=${encodeURIComponent(node)}`,
    signal,
  );
}
