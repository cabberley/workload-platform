import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { ApiError } from "../api/client";
import * as client from "../api/client";
import { BlastRadiusView } from "./BlastRadiusView";
import { makeGraph } from "../test/fixtures";
import type { ImpactResult } from "../api/types";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, fetchImpact: vi.fn() };
});

const fetchImpact = vi.mocked(client.fetchImpact);

beforeEach(() => {
  fetchImpact.mockReset();
});

const noop = () => {};

// n-web -> n-api (redundant) -> n-db (non-redundant). Simulate n-db failing: n-api goes down,
// n-web degrades (redundant to n-api). Mirrors the canonical server-side result shape.
function dbImpact(): ImpactResult {
  return {
    failedNode: "n-db",
    states: { "n-db": "down", "n-api": "down", "n-web": "degraded" },
    blastRadius: 1,
    down: ["n-api"],
    degraded: ["n-web"],
    graphRevision: "rev-fake-1", // matches makeGraph() → topology-consistent
  };
}

describe("BlastRadiusView", () => {
  it("recolors the graph and renders the blast-radius count + down/degraded lists", async () => {
    fetchImpact.mockResolvedValue(dbImpact());

    render(
      <BlastRadiusView
        workload="atlas"
        graph={makeGraph()}
        node="n-db"
        onSelectNode={noop}
        onClear={noop}
      />,
    );

    // Blast-radius count surfaces from the CANONICAL server value.
    expect(await screen.findByTestId("blast-radius-count")).toHaveTextContent("1");

    // Recolor: at least one DOWN node and one DEGRADED node are drawn (health labels in the SVG).
    await waitFor(() => expect(screen.getAllByText(/DOWN/).length).toBeGreaterThan(0));
    expect(screen.getAllByText(/DEGRADED/).length).toBeGreaterThan(0);

    // Down/degraded fallout lists render the exact node ids from the impact.
    const impact = screen.getByLabelText("Blast-radius impact");
    expect(within(impact).getByText("n-api")).toBeInTheDocument();
    expect(within(impact).getByText("n-web")).toBeInTheDocument();
  });

  it("marks the simulated node with a distinct SIMULATED FAILURE origin (not live health)", async () => {
    fetchImpact.mockResolvedValue(dbImpact());
    render(
      <BlastRadiusView
        workload="atlas"
        graph={makeGraph()}
        node="n-db"
        onSelectNode={noop}
        onClear={noop}
      />,
    );
    // The badge appears both in the header and on the node — it never reads as a live "down".
    await waitFor(() => expect(screen.getAllByText(/SIMULATED FAILURE/).length).toBeGreaterThan(0));
  });

  it("fails closed on a 404 / unknown node — explicit message, no false all-clear recolor", async () => {
    fetchImpact.mockRejectedValue(new ApiError(404, "404 Not Found"));

    render(
      <BlastRadiusView
        workload="atlas"
        graph={makeGraph()}
        node="ghost"
        onSelectNode={noop}
        onClear={noop}
      />,
    );

    await waitFor(() => expect(screen.getAllByRole("alert").length).toBeGreaterThan(0));
    expect(screen.getAllByText(/not an all-clear/).length).toBeGreaterThan(0);
    // No blast-radius count is shown (we never fall through to a "0 down" all-clear).
    expect(screen.queryByTestId("blast-radius-count")).not.toBeInTheDocument();
    // The failed node keeps its simulated-origin marker (never a live-health reinterpretation).
    expect(screen.getAllByText(/SIMULATED FAILURE/).length).toBeGreaterThan(0);
  });

  it("fails closed on a server error — explicit alert, no impact numbers", async () => {
    fetchImpact.mockRejectedValue(new ApiError(500, "500 boom"));
    render(
      <BlastRadiusView
        workload="atlas"
        graph={makeGraph()}
        node="n-db"
        onSelectNode={noop}
        onClear={noop}
      />,
    );
    await waitFor(() => expect(screen.getAllByRole("alert").length).toBeGreaterThan(0));
    expect(screen.queryByTestId("blast-radius-count")).not.toBeInTheDocument();
  });

  it("withholds recolor + count when the impact topology diverges from the displayed graph", async () => {
    // Displayed graph has 3 nodes (n-web/n-api/n-db); this impact was computed on a DIFFERENT
    // topology (n-web missing from `states`) — e.g. the persisted graph changed between fetches.
    fetchImpact.mockResolvedValue({
      failedNode: "n-db",
      states: { "n-db": "down", "n-api": "down" },
      blastRadius: 1,
      down: ["n-api"],
      degraded: [],
      graphRevision: "rev-fake-1",
    } satisfies ImpactResult);

    render(
      <BlastRadiusView
        workload="atlas"
        graph={makeGraph()}
        node="n-db"
        onSelectNode={noop}
        onClear={noop}
      />,
    );

    // Explicit "graph changed" fail-closed message; new-topology impact is NOT applied to the render.
    await waitFor(() => expect(screen.getAllByRole("alert").length).toBeGreaterThan(0));
    expect(screen.getAllByText(/reload to re-run/i).length).toBeGreaterThan(0);
    // No blast-radius number is shown (never a false all-clear against a stale graph).
    expect(screen.queryByTestId("blast-radius-count")).not.toBeInTheDocument();
    // No node is recolored inside the graph — nodes stay "unknown" (legend swatches are excluded).
    const graphArea = screen.getByLabelText("Blast-radius simulation graph");
    expect(within(graphArea).queryByText(/DOWN|DEGRADED/)).not.toBeInTheDocument();
    expect(within(graphArea).getAllByText(/UNKNOWN/).length).toBeGreaterThan(0);
  });

  it("withholds recolor on EDGE-LEVEL staleness: identical node set but a different graphRevision", async () => {
    // Same node ids AND a valid failedNode — a node-set check alone would MISS this — but the
    // server-computed revision differs (an edge was added/removed on the persisted graph). The
    // opaque revision mismatch must fail closed: no recolor, no count, explicit alert.
    fetchImpact.mockResolvedValue({
      failedNode: "n-db",
      states: { "n-db": "down", "n-api": "up", "n-web": "up" }, // impact says n-api is UP now
      blastRadius: 0,
      down: [],
      degraded: [],
      graphRevision: "rev-fake-2-EDGE-CHANGED", // != makeGraph()'s "rev-fake-1"
    } satisfies ImpactResult);

    render(
      <BlastRadiusView
        workload="atlas"
        graph={makeGraph()}
        node="n-db"
        onSelectNode={noop}
        onClear={noop}
      />,
    );

    await waitFor(() => expect(screen.getAllByText(/reload to re-run/i).length).toBeGreaterThan(0));
    // The false all-clear (blast radius 0 / n-api up on the NEW topology) is NOT painted.
    expect(screen.queryByTestId("blast-radius-count")).not.toBeInTheDocument();
    const graphArea = screen.getByLabelText("Blast-radius simulation graph");
    expect(within(graphArea).getAllByText(/UNKNOWN/).length).toBeGreaterThan(0);
  });

  it("fails closed when the displayed graph has NO graphRevision (absence is divergence)", async () => {
    // A displayed graph without a revision (older/cached response, or any consumer that doesn't
    // populate it) must NOT fall back to the insufficient node-set-only check: absence itself is
    // fail-closed. Impact has an identical node set + valid failedNode, so a node-set check alone
    // would (wrongly) pass and paint a false zero-radius all-clear.
    fetchImpact.mockResolvedValue({
      failedNode: "n-db",
      states: { "n-db": "down", "n-api": "up", "n-web": "up" },
      blastRadius: 0,
      down: [],
      degraded: [],
      graphRevision: "rev-fake-1",
    } satisfies ImpactResult);

    render(
      <BlastRadiusView
        workload="atlas"
        graph={makeGraph({ graphRevision: undefined })}
        node="n-db"
        onSelectNode={noop}
        onClear={noop}
      />,
    );

    await waitFor(() => expect(screen.getAllByText(/reload to re-run/i).length).toBeGreaterThan(0));
    // No false all-clear: no blast-radius count, and the graph is not recolored (stays UNKNOWN).
    expect(screen.queryByTestId("blast-radius-count")).not.toBeInTheDocument();
    const graphArea = screen.getByLabelText("Blast-radius simulation graph");
    expect(within(graphArea).getAllByText(/UNKNOWN/).length).toBeGreaterThan(0);
  });

  it("also diverges when the selected failedNode is not in the displayed graph", async () => {
    fetchImpact.mockResolvedValue({
      failedNode: "ghost",
      states: { ghost: "down" },
      blastRadius: 0,
      down: [],
      degraded: [],
      graphRevision: "rev-fake-1",
    } satisfies ImpactResult);

    render(
      <BlastRadiusView
        workload="atlas"
        graph={makeGraph()}
        node="ghost"
        onSelectNode={noop}
        onClear={noop}
      />,
    );

    await waitFor(() => expect(screen.getAllByText(/reload to re-run/i).length).toBeGreaterThan(0));
    expect(screen.queryByTestId("blast-radius-count")).not.toBeInTheDocument();
  });

  it("aborts the previous impact request when the simulated node changes (no piled-up work)", async () => {
    const signals: AbortSignal[] = [];
    fetchImpact.mockImplementation((_workload, _node, signal) => {
      if (signal) signals.push(signal);
      return new Promise<ImpactResult>(() => {}); // never resolves — stays in flight
    });

    const shared = { workload: "atlas", graph: makeGraph(), onSelectNode: noop, onClear: noop };
    const { rerender } = render(<BlastRadiusView key="n-db" node="n-db" {...shared} />);
    await waitFor(() => expect(signals.length).toBe(1));

    // Re-selecting a different node remounts (key change) → the prior request must be ABORTED.
    rerender(<BlastRadiusView key="n-api" node="n-api" {...shared} />);
    await waitFor(() => expect(signals.length).toBe(2));

    expect(signals[0].aborted).toBe(true);
    expect(signals[1].aborted).toBe(false);
  });
});
