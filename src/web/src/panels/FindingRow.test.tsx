import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingRow, passState } from "../panels/FindingRow";
import { makeFinding } from "../test/fixtures";

describe("passState (tri-state, fail-closed)", () => {
  it("only true is a pass", () => {
    expect(passState(true)).toBe("pass");
  });
  it("false is a fail", () => {
    expect(passState(false)).toBe("fail");
  });
  it("null is unknown — NOT a pass (fail-closed)", () => {
    expect(passState(null)).toBe("unknown");
  });
});

describe("FindingRow provenance", () => {
  it("renders title, module, severity, blast radius and full provenance", () => {
    render(
      <FindingRow
        finding={makeFinding({
          title: "Backups configured",
          module: "aiops",
          severity: "high",
          blastRadius: 7,
          packId: "rule.backup.fake",
          packVersion: "9.9.9",
          createdAt: "2026-02-03T04:05:06Z",
          evidence: [{ kind: "metric", id: "fake/metric/id", detail: "synthetic sample" }],
        })}
      />,
    );

    expect(screen.getByText("Backups configured")).toBeInTheDocument();
    expect(screen.getByText("aiops")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    // Evidence (SourceReference kind/id/detail) is required on every finding.
    expect(screen.getByText("metric")).toBeInTheDocument();
    expect(screen.getByText("fake/metric/id")).toBeInTheDocument();
    expect(screen.getByText(/synthetic sample/)).toBeInTheDocument();
    // pack@version + createdAt provenance.
    expect(screen.getByText("rule.backup.fake@9.9.9")).toBeInTheDocument();
    expect(screen.getByText("2026-02-03T04:05:06Z")).toBeInTheDocument();
  });

  it("shows PASS only when passed === true", () => {
    render(<FindingRow finding={makeFinding({ passed: true })} />);
    expect(screen.getByText(/PASS/)).toBeInTheDocument();
    expect(screen.queryByText(/FAIL/)).not.toBeInTheDocument();
  });

  it("shows FAIL when passed === false", () => {
    render(<FindingRow finding={makeFinding({ passed: false })} />);
    expect(screen.getByText(/FAIL/)).toBeInTheDocument();
  });

  it("shows UNKNOWN (not passing) when passed === null — never a false all-clear", () => {
    render(<FindingRow finding={makeFinding({ passed: null })} />);
    expect(screen.getByText(/UNKNOWN/)).toBeInTheDocument();
    expect(screen.getByText(/not passing/)).toBeInTheDocument();
    // Must not read as a pass.
    expect(screen.queryByText(/✓ PASS/)).not.toBeInTheDocument();
  });

  it("flags a finding with no evidence as unverified (provenance guardrail, fail-closed)", () => {
    render(<FindingRow finding={makeFinding({ evidence: [] })} />);
    expect(screen.getByText(/No evidence cited/)).toBeInTheDocument();
  });

  it("renders unknown pack provenance when packId/packVersion are null", () => {
    render(
      <FindingRow
        finding={makeFinding({
          provenance: "structural",
          structuralKind: "spof",
          packId: null,
          packVersion: null,
        })}
      />,
    );
    expect(screen.getByText("unknown@unknown")).toBeInTheDocument();
  });
});
