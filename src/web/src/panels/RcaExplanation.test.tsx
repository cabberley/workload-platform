import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { RcaExplanation, selectRcaExplanations, advisoriesToViews } from "../panels/RcaExplanation";
import { makeAgentResponse, makeRcaAdvisory } from "../test/fixtures";

describe("selectRcaExplanations (pure UI join, fail-closed)", () => {
  it("pairs each RCA with its index-aligned non-empty advisory", () => {
    const rca = [makeAgentResponse(), makeAgentResponse({ agentName: "aiops-2" })];
    const views = selectRcaExplanations(rca, [
      { advisory: "first advisory" },
      { advisory: "second advisory" },
    ]);
    expect(views).toHaveLength(2);
    expect(views[0].advisory).toBe("first advisory");
    expect(views[1].rca.agentName).toBe("aiops-2");
  });

  it("drops entries whose advisory is empty/blank (no-op edge is fail-closed)", () => {
    const rca = [makeAgentResponse(), makeAgentResponse({ agentName: "aiops-2" })];
    const views = selectRcaExplanations(rca, [{ advisory: "" }, { advisory: "   " }]);
    expect(views).toEqual([]);
  });

  it("returns [] when rca or explanations are absent", () => {
    expect(selectRcaExplanations(null, [{ advisory: "x" }])).toEqual([]);
    expect(selectRcaExplanations([makeAgentResponse()], null)).toEqual([]);
    expect(selectRcaExplanations(undefined, undefined)).toEqual([]);
  });

  it("only keeps the RCA that carries an advisory when they are unevenly aligned", () => {
    const rca = [makeAgentResponse(), makeAgentResponse({ agentName: "aiops-2" })];
    const views = selectRcaExplanations(rca, [{ advisory: "" }, { advisory: "kept" }]);
    expect(views).toHaveLength(1);
    expect(views[0].advisory).toBe("kept");
    expect(views[0].rca.agentName).toBe("aiops-2");
  });
});

describe("advisoriesToViews (backend read-model adapter, fail-closed)", () => {
  it("shapes each persisted RcaAdvisory into a renderable view", () => {
    const views = advisoriesToViews([
      makeRcaAdvisory({ advisory: "first" }),
      makeRcaAdvisory({ index: 1, agentName: "aiops-2", advisory: "second" }),
    ]);
    expect(views).toHaveLength(2);
    expect(views[0].advisory).toBe("first");
    expect(views[1].rca.agentName).toBe("aiops-2");
    // The cited evidence carries through so the panel can show it alongside the advisory.
    expect(views[0].rca.sourceReferences.map((r) => r.id)).toContain("/fake/resource/widget-01");
  });

  it("drops empty/blank advisories and returns [] when absent", () => {
    expect(advisoriesToViews([makeRcaAdvisory({ advisory: "" }), makeRcaAdvisory({ advisory: "  " })])).toEqual([]);
    expect(advisoriesToViews(null)).toEqual([]);
    expect(advisoriesToViews(undefined)).toEqual([]);
  });

  it("carries the persisted grounding evidence (findings/risks/recs) into the view (MED-5)", () => {
    const views = advisoriesToViews([
      makeRcaAdvisory({
        findings: ["web01.contoso.com is unreachable"],
        risks: ["availability at risk"],
        recommendations: ["restart the cited node"],
      }),
    ]);
    expect(views).toHaveLength(1);
    expect(views[0].rca.findings).toEqual(["web01.contoso.com is unreachable"]);
    expect(views[0].rca.risks).toEqual(["availability at risk"]);
    expect(views[0].rca.recommendations).toEqual(["restart the cited node"]);
  });
});

describe("RcaExplanation component", () => {
  it("renders the advisory, the AI-advisory labelling and the cited evidence", () => {
    const rca = makeAgentResponse();
    render(
      <RcaExplanation
        views={[{ rca, advisory: "The evidence indicates node-fake-01 is saturated." }]}
      />,
    );

    // Clearly labelled as an AI advisory with "human disposes" framing.
    expect(screen.getByText(/AI ADVISORY/)).toBeInTheDocument();
    expect(screen.getByText(/human disposes/i)).toBeInTheDocument();
    // The advisory text.
    expect(
      screen.getByText(/The evidence indicates node-fake-01 is saturated\./),
    ).toBeInTheDocument();
    // The cited evidence is shown alongside so an operator can verify.
    expect(screen.getByText("/fake/resource/widget-01")).toBeInTheDocument();
    expect(screen.getByText("cpu_saturation_ratio")).toBeInTheDocument();
    // Confidence surfaced.
    expect(screen.getByText("0.90")).toBeInTheDocument();
  });

  it("renders nothing when there are no explanations (graceful, fail-closed)", () => {
    const { container } = render(<RcaExplanation views={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("flags an advisory whose RCA cites no evidence as unverified", () => {
    const rca = makeAgentResponse({ sourceReferences: [] });
    render(<RcaExplanation views={[{ rca, advisory: "grounded prose" }]} />);
    expect(screen.getByText(/No evidence cited/)).toBeInTheDocument();
  });

  it("displays the grounding findings/risks/recommendations as cited evidence (MED-5)", () => {
    const rca = makeAgentResponse({
      findings: ["web01.contoso.com is unreachable"],
      risks: ["availability at risk for widget"],
      recommendations: ["restart the cited node"],
    });
    render(<RcaExplanation views={[{ rca, advisory: "grounded on the finding" }]} />);
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText(/web01\.contoso\.com is unreachable/)).toBeInTheDocument();
    expect(screen.getByText("Risks")).toBeInTheDocument();
    expect(screen.getByText(/availability at risk for widget/)).toBeInTheDocument();
    expect(screen.getByText("Recommendations")).toBeInTheDocument();
    expect(screen.getByText(/restart the cited node/)).toBeInTheDocument();
  });
});
