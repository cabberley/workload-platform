// Read-only API client for the platform read models. Every call is a GET — the console never
// writes state (no POST/PUT/DELETE anywhere in the SPA). Requests hit the same origin; the dev
// server proxies `/api` to the FastAPI core (see `vite.config.ts`).

import type {
  DriftReport,
  Finding,
  ModuleManifest,
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

async function getJson<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { method: "GET", headers: { Accept: "application/json" } });
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
