import type { CSSProperties } from "react";
import type { Finding } from "../api/types";
import { SEVERITY_COLOR } from "../graph/encodings";

/** Tri-state pass/fail, fail-closed. Only `passed === true` is a pass; `false` AND `null` are both
 *  treated as NOT passing — an unknown result must never read as an all-clear. Pure so it can be
 *  unit-tested directly. */
export type PassState = "pass" | "fail" | "unknown";

export function passState(passed: boolean | null): PassState {
  if (passed === true) return "pass";
  if (passed === false) return "fail";
  return "unknown";
}

const PASS_ENCODING: Record<PassState, { glyph: string; label: string; color: string }> = {
  // Colour is never the only cue — each state also carries a glyph + word (house a11y rule).
  pass: { glyph: "✓", label: "PASS", color: "#137333" },
  fail: { glyph: "✕", label: "FAIL", color: "#a50e0e" },
  unknown: { glyph: "◇", label: "UNKNOWN — not passing", color: "#5f6368" },
};

/**
 * One finding, with its full provenance (Provenance guardrail): title, producing module, severity,
 * tri-state pass/fail, blast radius, its evidence (`SourceReference[]`) and the signed pack it came
 * from (`packId@packVersion`) plus `createdAt`. Reused by the Findings and Drift views.
 */
export function FindingRow({ finding }: { finding: Finding }) {
  const pass = passState(finding.passed);
  const passEnc = PASS_ENCODING[pass];
  const sevColor = SEVERITY_COLOR[finding.severity];

  return (
    <article aria-label={`Finding ${finding.title}`} style={row}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}>
        <strong style={{ fontSize: 14 }}>{finding.title}</strong>
        <code style={{ fontSize: 11, color: "#5f6368" }}>{finding.module}</code>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginTop: 6 }}>
        <span style={chip(sevColor)}>{finding.severity}</span>
        <span style={{ ...chip(passEnc.color), textTransform: "none" }}>
          {passEnc.glyph} {passEnc.label}
        </span>
        <span style={{ fontSize: 12, color: "#5f6368", fontVariantNumeric: "tabular-nums" }}>
          blast radius <strong>{finding.blastRadius}</strong>
        </span>
        {finding.nodeId && (
          <code style={{ fontSize: 11, color: "#5f6368" }}>node: {finding.nodeId}</code>
        )}
      </div>

      {finding.detail && (
        <p style={{ margin: "6px 0 0", fontSize: 13, color: "#3c4043" }}>{finding.detail}</p>
      )}

      {/* Provenance — required on every finding. */}
      <div style={{ marginTop: 8, fontSize: 12 }}>
        <div style={{ fontWeight: 600, color: "#3c4043" }}>Evidence</div>
        {finding.evidence.length === 0 ? (
          <p style={{ margin: "2px 0 0", color: "#a50e0e" }}>
            ⚠ No evidence cited — treat as unverified (fail-closed).
          </p>
        ) : (
          <ul style={{ margin: "2px 0 0", paddingLeft: 18 }}>
            {finding.evidence.map((ref, i) => (
              <li key={`${ref.kind}:${ref.id}:${i}`} style={{ marginBottom: 2 }}>
                <span style={{ color: "#5f6368" }}>{ref.kind}</span>{" "}
                <code style={{ fontSize: 11 }}>{ref.id}</code>
                {ref.detail && <span style={{ color: "#5f6368" }}> — {ref.detail}</span>}
              </li>
            ))}
          </ul>
        )}
        <div style={{ marginTop: 6, color: "#5f6368" }}>
          pack{" "}
          <code style={{ fontSize: 11 }}>
            {finding.packId ?? "unknown"}@{finding.packVersion ?? "unknown"}
          </code>{" "}
          · <time dateTime={finding.createdAt}>{finding.createdAt}</time>
        </div>
      </div>
    </article>
  );
}

const row: CSSProperties = {
  border: "1px solid #e0e0e0",
  borderRadius: 8,
  padding: 12,
  background: "#fff",
};

function chip(color: string): CSSProperties {
  return {
    display: "inline-block",
    border: `1px solid ${color}`,
    color,
    borderRadius: 4,
    padding: "1px 6px",
    fontSize: 11,
    fontWeight: 700,
    textTransform: "uppercase",
  };
}
