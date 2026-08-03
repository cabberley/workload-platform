import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { ApiError } from "../api/client";
import * as client from "../api/client";
import type { AsyncState } from "../hooks/useAsync";
import { EstateView, GRAPH_FETCH_CONCURRENCY } from "./EstateView";
import { makeGraph } from "../test/fixtures";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, fetchGraph: vi.fn() };
});

const fetchGraph = vi.mocked(client.fetchGraph);

function ok(data: string[]): AsyncState<string[]> {
  return { status: "success", data };
}

beforeEach(() => {
  fetchGraph.mockReset();
});

describe("EstateView", () => {
  it("derives a per-workload dependency summary from each graph", async () => {
    fetchGraph.mockResolvedValue(makeGraph());
    render(<EstateView state={ok(["atlas"])} />);

    expect(await screen.findByText("atlas")).toBeInTheDocument();
    // node count 3, edge count 2 from the fixture graph.
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    // one non-redundant edge reported as a factual single-path property (no risk/SPOF wording).
    expect(screen.getByText(/single-path edge/)).toBeInTheDocument();
    expect(screen.getByText(/most depended-on/)).toBeInTheDocument();
    // No SPOF language, and blast radius is only ever mentioned to disclaim it (never as a label).
    expect(screen.queryByText(/SPOF/i)).not.toBeInTheDocument();
    expect(screen.getByText(/not blast radius/i)).toBeInTheDocument();
  });

  it("handles the 404 no-graph case gracefully (not an error)", async () => {
    fetchGraph.mockRejectedValue(new ApiError(404, "404 Not Found"));
    render(<EstateView state={ok(["atlas"])} />);
    expect(await screen.findByText(/No dependency graph yet/)).toBeInTheDocument();
  });

  it("fails closed on a non-404 graph error", async () => {
    fetchGraph.mockRejectedValue(new ApiError(500, "500 boom"));
    render(<EstateView state={ok(["atlas"])} />);
    await waitFor(() => expect(screen.getByText(/Not an all-clear/)).toBeInTheDocument());
  });

  it("treats a successful BUT EMPTY graph as unverified — never an all-clear", async () => {
    fetchGraph.mockResolvedValue({ nodes: [], edges: [] });
    render(<EstateView state={ok(["atlas"])} />);
    expect(await screen.findByText(/Empty graph — dependencies unverified/)).toBeInTheDocument();
    // Must NOT render the populated-graph "all edges redundant" all-clear text.
    expect(screen.queryByText(/all edges redundant/)).not.toBeInTheDocument();
  });

  it("treats a nodes-but-ZERO-edges graph as unverified — not verified redundancy/all-clear", async () => {
    fetchGraph.mockResolvedValue({
      nodes: [
        { id: "n1", name: "n1", type: "app", workload: "atlas", tier: "web", role: "frontend", tags: {} },
      ],
      edges: [],
    });
    render(<EstateView state={ok(["atlas"])} />);
    expect(await screen.findByText(/No dependency edges recorded/)).toBeInTheDocument();
    // Zero-edge must NOT read as clean/redundant.
    expect(screen.queryByText(/all edges redundant/)).not.toBeInTheDocument();
    expect(screen.queryByText(/most depended-on/)).not.toBeInTheDocument();
  });

  it("shows an empty-estate message when no workloads exist", () => {
    render(<EstateView state={ok([])} />);
    expect(screen.getByText(/No workloads discovered yet/)).toBeInTheDocument();
    expect(fetchGraph).not.toHaveBeenCalled();
  });

  it("surfaces a workloads-list error (fail-closed)", () => {
    const errState: AsyncState<string[]> = { status: "error", error: new Error("list boom") };
    render(<EstateView state={errState} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/not an all-clear/i);
  });

  it("bounds concurrency — does not fire N requests at once for a large estate", async () => {
    // Never-resolving graphs so every worker stays parked on its first in-flight request.
    fetchGraph.mockReturnValue(new Promise<never>(() => {}));
    const workloads = Array.from({ length: 12 }, (_, i) => `wl-${i}`);

    render(<EstateView state={ok(workloads)} />);

    // At most `GRAPH_FETCH_CONCURRENCY` requests are in flight, not all 12.
    await waitFor(() => expect(fetchGraph).toHaveBeenCalledTimes(GRAPH_FETCH_CONCURRENCY));
    expect(GRAPH_FETCH_CONCURRENCY).toBeLessThan(workloads.length);
    expect(fetchGraph.mock.calls.length).toBe(GRAPH_FETCH_CONCURRENCY);
  });
});
