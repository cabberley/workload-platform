import { useMemo, useState } from "react";
import { fetchPacks } from "../api/client";
import type { PackRegistryEntry } from "../api/types";
import { useAsync } from "../hooks/useAsync";
import { muted, td, th } from "../styles";

/** Shorten a sha256 content-address for display (never the identity used for any decision). */
function shortDigest(digest: string): string {
  return digest.length > 12 ? `${digest.slice(0, 12)}…` : digest;
}

/**
 * Pack-version management console (issue #57).
 *
 * Two surfaces over the EXISTING pack registry (issue #34):
 *  1. Catalogue — lists every published pack version from the registry read surface
 *     (`GET /api/packs`, the keyless/PII-free projection of `packs_engine.registry`). Fail-closed:
 *     an empty catalogue is "nothing published", never an all-clear.
 *  2. Per-workload assignment — view + assign a signed pack version for the selected workload.
 *
 * READ-ONLY assignment BY DESIGN. The pack→workload ASSIGNMENT backend (registry-bound, digest-safe
 * — issue #37 / #36) is NOT present in `main` on this branch: there is no assignment API route, no
 * `PackAssignmentsTable`, and no assignment state. Per the guardrails an assignment is a *write*
 * that MUST go through that validated, registry-bound backend, so we do NOT fabricate an endpoint,
 * a current-assignment read, or customer data. The assign control is rendered but disabled, and
 * only SIGNED versions would ever be assignable (fail closed).
 *
 * TODO(human): wire real assignment once the backend exists in `main`. Needed there first:
 *  - a per-workload assignment READ route (e.g. `GET /api/workloads/{workload}/pack-assignments`)
 *    projecting the assignment state, and
 *  - a validated, registry-bound assignment WRITE route (the #37 surface) that binds a workload to
 *    a specific published `id@version` by its verified registry digest (digest-safe), refuses
 *    unsigned/unknown refs (fail closed), and emits the `AuditAction.pack_assign` event reserved at
 *    `src/cli/wiring.py` / `src/shared/contracts.py` (issue #59).
 * When both land: add `fetchAssignments(workload)` + a keyless `assignPack(workload, ref)` client
 * call, reuse the #37 `PackAssignmentsTable` pattern, enable the control for signed versions only,
 * and reflect the server-confirmed assignment (revert + surface on any non-2xx).
 */
export function PacksConsole({ workload }: { workload: string | null }) {
  const state = useAsync<PackRegistryEntry[]>(() => fetchPacks(), []);
  const packs = state.status === "success" ? state.data : [];

  if (state.status === "loading") {
    return <p style={muted}>Loading pack registry…</p>;
  }
  if (state.status === "error") {
    return (
      <p style={{ color: "crimson" }} role="alert">
        Could not load the pack registry ({state.error.message}). This is not an all-clear — the
        pack catalogue is unknown.
      </p>
    );
  }

  return (
    <section aria-label="Pack-version management" style={{ display: "grid", gap: 20 }}>
      <div>
        <h3 style={{ margin: "0 0 8px", fontSize: 16 }}>Published pack versions</h3>
        <PackCatalogue packs={packs} />
      </div>
      <WorkloadAssignment workload={workload} packs={packs} />
    </section>
  );
}

/** The registry catalogue — one row per published, content-addressed pack version. */
function PackCatalogue({ packs }: { packs: PackRegistryEntry[] }) {
  if (packs.length === 0) {
    // Fail-closed: no published versions is absence of a catalogue, not a verified/clean state.
    return (
      <p style={{ color: "#b06000" }}>
        No pack versions published — the registry is empty or not wired (not an all-clear).
      </p>
    );
  }
  return (
    <table style={{ borderCollapse: "collapse", width: "100%" }}>
      <thead>
        <tr>
          <th style={th}>Pack</th>
          <th style={th}>Version</th>
          <th style={th}>Type</th>
          <th style={th}>Signed</th>
          <th style={th}>Digest</th>
        </tr>
      </thead>
      <tbody>
        {packs.map((p) => (
          <tr key={`${p.id}@${p.version}`}>
            <td style={td}>
              <code>{p.id}</code>
            </td>
            <td style={td}>{p.version}</td>
            <td style={td}>{p.type}</td>
            <td style={td}>
              {p.signed ? (
                <span style={{ color: "#137333", fontWeight: 600 }}>signed</span>
              ) : (
                <span style={{ color: "#b06000", fontWeight: 600 }}>unsigned</span>
              )}
            </td>
            <td style={td}>
              <code style={{ fontSize: 11 }} title={p.digest}>
                {shortDigest(p.digest)}
              </code>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Per-workload assignment view. Read-only: the assignment backend does not exist on this branch, so
 * the current assignment is UNKNOWN (never rendered as "none"/all-clear) and the assign control is
 * disabled. Only signed versions are offered as candidates (fail closed).
 */
function WorkloadAssignment({
  workload,
  packs,
}: {
  workload: string | null;
  packs: PackRegistryEntry[];
}) {
  const signed = useMemo(() => packs.filter((p) => p.signed), [packs]);
  const [ref, setRef] = useState<string>("");

  return (
    <div>
      <h3 style={{ margin: "0 0 8px", fontSize: 16 }}>Assign a signed pack version</h3>
      {workload === null ? (
        <p style={muted}>Select a workload above to view and assign its pack versions.</p>
      ) : (
        <>
          <p style={{ ...muted, marginTop: 0 }}>
            Workload <strong>{workload}</strong> — current assignment:{" "}
            <span style={{ color: "#b06000" }}>
              unavailable (no assignment backend — not &quot;none&quot;)
            </span>
            .
          </p>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <label htmlFor="pack-version" style={muted}>
              Signed version:
            </label>
            <select
              id="pack-version"
              value={ref}
              onChange={(e) => setRef(e.target.value)}
              disabled={signed.length === 0}
              style={{ padding: "4px 8px", fontSize: 13 }}
            >
              <option value="">
                {signed.length === 0 ? "no signed versions available" : "select a version…"}
              </option>
              {signed.map((p) => (
                <option key={`${p.id}@${p.version}`} value={`${p.id}@${p.version}`}>
                  {p.id}@{p.version}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled
              title="Assignment requires a validated, registry-bound backend surface (not yet available)"
              style={{
                padding: "5px 12px",
                fontSize: 13,
                borderRadius: 6,
                border: "1px solid #ccc",
                background: "#f1f3f4",
                color: "#5f6368",
                cursor: "not-allowed",
              }}
            >
              Assign
            </button>
          </div>
          <p style={{ ...muted, fontSize: 12, marginBottom: 0 }}>
            Assignment is disabled until a validated, registry-bound assignment backend exists — all
            writes must go through it (never the console). Only signed versions are assignable.
          </p>
        </>
      )}
    </div>
  );
}
