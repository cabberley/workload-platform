import type { ReactNode } from "react";
import { ApiError, fetchDrift } from "../api/client";
import type { DriftReport, Finding } from "../api/types";
import { useAsync } from "../hooks/useAsync";
import { FindingRow } from "./FindingRow";
import { muted } from "../styles";

/**
 * Renders the FULL drift report (reassessment deltas across runs) — new / recovered / still-failing
 * findings plus added / removed nodes. The existing `DriftBadge` only summarises counts; this view
 * shows every delta. Fail-closed: loading / error / 404 are surfaced, never a false "no drift".
 */
export function DriftView({ workload }: { workload: string }) {
  const state = useAsync<DriftReport>(() => fetchDrift(workload), [workload]);

  if (state.status === "loading") {
    return <p style={muted}>Loading drift…</p>;
  }
  if (state.status === "error") {
    if (state.error instanceof ApiError && state.error.status === 404) {
      return (
        <p style={muted}>
          No drift baseline for <strong>{workload}</strong> yet. Drift appears after a second
          reassessment run.
        </p>
      );
    }
    return (
      <p style={{ color: "crimson" }} role="alert">
        Could not load drift ({state.error.message}). This is not an all-clear.
      </p>
    );
  }

  const report = state.data;
  const nothing =
    report.newFailures.length === 0 &&
    report.recovered.length === 0 &&
    report.stillFailing.length === 0 &&
    report.addedNodes.length === 0 &&
    report.removedNodes.length === 0;

  return (
    <section aria-label="Drift" style={{ display: "grid", gap: 16 }}>
      {nothing && (
        <p style={muted}>
          No drift detected for <strong>{workload}</strong> since the previous snapshot.
        </p>
      )}

      <FindingsSection
        title="New failures"
        glyph="▲"
        color="#a50e0e"
        findings={report.newFailures}
        emptyLabel="No new failures."
      />
      <FindingsSection
        title="Recovered"
        glyph="▼"
        color="#137333"
        findings={report.recovered}
        emptyLabel="Nothing recovered."
      />
      <FindingsSection
        title="Still failing"
        glyph="■"
        color="#b06000"
        findings={report.stillFailing}
        emptyLabel="Nothing still failing."
      />

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <NodeSection title="Added nodes" glyph="＋" color="#137333" nodes={report.addedNodes} />
        <NodeSection title="Removed nodes" glyph="－" color="#a50e0e" nodes={report.removedNodes} />
      </div>
    </section>
  );
}

function SectionHeading({ glyph, color, title, count }: { glyph: string; color: string; title: string; count: number }) {
  return (
    <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>
      <span style={{ color }}>{glyph}</span> {title}{" "}
      <span style={{ ...muted, fontWeight: 400 }}>({count})</span>
    </h3>
  );
}

function FindingsSection({
  title,
  glyph,
  color,
  findings,
  emptyLabel,
}: {
  title: string;
  glyph: string;
  color: string;
  findings: Finding[];
  emptyLabel: string;
}) {
  return (
    <section aria-label={title}>
      <SectionHeading glyph={glyph} color={color} title={title} count={findings.length} />
      {findings.length === 0 ? (
        <p style={muted}>{emptyLabel}</p>
      ) : (
        <div style={{ display: "grid", gap: 10 }}>
          {findings.map((f) => (
            <FindingRow key={f.id} finding={f} />
          ))}
        </div>
      )}
    </section>
  );
}

function NodeSection({ title, glyph, color, nodes }: { title: string; glyph: string; color: string; nodes: string[] }): ReactNode {
  return (
    <section aria-label={title}>
      <SectionHeading glyph={glyph} color={color} title={title} count={nodes.length} />
      {nodes.length === 0 ? (
        <p style={muted}>None.</p>
      ) : (
        <ul style={{ margin: 0, paddingLeft: 18 }}>
          {nodes.map((n) => (
            <li key={n} style={{ fontSize: 13 }}>
              <code style={{ fontSize: 11 }}>{n}</code>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
