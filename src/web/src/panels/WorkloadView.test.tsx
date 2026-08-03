import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as client from "../api/client";
import { WorkloadView } from "./WorkloadView";
import { makeGraph, makeDrift } from "../test/fixtures";
import type { ImpactResult } from "../api/types";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    fetchGraph: vi.fn(),
    fetchFindings: vi.fn(),
    fetchDrift: vi.fn(),
    fetchImpact: vi.fn(),
  };
});

const fetchGraph = vi.mocked(client.fetchGraph);
const fetchFindings = vi.mocked(client.fetchFindings);
const fetchDrift = vi.mocked(client.fetchDrift);
const fetchImpact = vi.mocked(client.fetchImpact);

beforeEach(() => {
  fetchGraph.mockReset();
  fetchFindings.mockReset();
  fetchDrift.mockReset();
  fetchImpact.mockReset();
  fetchGraph.mockResolvedValue(makeGraph());
  fetchFindings.mockResolvedValue([]); // no findings → live view shows every node UP
  fetchDrift.mockResolvedValue(makeDrift());
  fetchImpact.mockResolvedValue({
    failedNode: "n-db",
    states: { "n-db": "down", "n-api": "down", "n-web": "degraded" },
    blastRadius: 1,
    down: ["n-api"],
    degraded: ["n-web"],
    graphRevision: "rev-fake-1",
  } satisfies ImpactResult);
});

describe("WorkloadView blast-radius simulation", () => {
  it("switches to a simulation on pick, recolors, then restores live health on clear", async () => {
    render(<WorkloadView workload="atlas" />);

    // Live view first: the SPOF panel is present and no simulation is active.
    expect(await screen.findByText(/SPOFs by blast radius/)).toBeInTheDocument();
    expect(screen.queryByTestId("blast-radius-count")).not.toBeInTheDocument();

    // Pick a node to simulate its failure.
    await userEvent.selectOptions(screen.getByRole("combobox"), "n-db");

    // Simulation view: canonical blast-radius count + a degraded fallout node render.
    expect(await screen.findByTestId("blast-radius-count")).toHaveTextContent("1");
    await waitFor(() => expect(screen.getAllByText(/DEGRADED/).length).toBeGreaterThan(0));
    expect(fetchImpact).toHaveBeenCalledWith("atlas", "n-db", expect.anything());
    // The live SPOF panel is gone while simulating (no mixing of simulated + live health).
    expect(screen.queryByText(/SPOFs by blast radius/)).not.toBeInTheDocument();

    // Clear the simulation → back to live health.
    await userEvent.click(screen.getByRole("button", { name: /Clear simulation/ }));

    expect(await screen.findByText(/SPOFs by blast radius/)).toBeInTheDocument();
    expect(screen.queryByTestId("blast-radius-count")).not.toBeInTheDocument();
  });

  it("disables the node picker while an impact computation is in flight", async () => {
    // An impact fetch that never resolves keeps the simulation in its loading state.
    fetchImpact.mockImplementation(() => new Promise(() => {}));

    render(<WorkloadView workload="atlas" />);
    await screen.findByText(/SPOFs by blast radius/);

    await userEvent.selectOptions(screen.getByRole("combobox"), "n-db");

    // While computing, the picker is disabled so rapid re-selection can't queue extra traversals.
    await waitFor(() => expect(screen.getByRole("combobox")).toBeDisabled());
  });

  it("guards clear + picker while in flight and never leaves them stuck (no stale leak)", async () => {
    // First simulation resolves only when we say so; the second uses the default resolved value.
    let resolveFirst!: (v: ImpactResult) => void;
    const first = new Promise<ImpactResult>((r) => {
      resolveFirst = r;
    });
    const apiImpact: ImpactResult = {
      failedNode: "n-api",
      states: { "n-api": "down", "n-web": "degraded", "n-db": "up" },
      blastRadius: 0,
      down: [],
      degraded: ["n-web"],
      graphRevision: "rev-fake-1",
    };
    fetchImpact.mockReset();
    fetchImpact.mockImplementationOnce(() => first).mockResolvedValue(apiImpact);

    render(<WorkloadView workload="atlas" />);
    await screen.findByText(/SPOFs by blast radius/);

    // Select n-db → in flight → BOTH the picker and the Clear button are disabled.
    await userEvent.selectOptions(screen.getByRole("combobox"), "n-db");
    await waitFor(() => expect(screen.getByRole("combobox")).toBeDisabled());
    expect(screen.getByRole("button", { name: /Clear simulation/ })).toBeDisabled();

    // Settle the first request → controls re-enable (busy clears in the success terminal state).
    resolveFirst({
      failedNode: "n-db",
      states: { "n-db": "down", "n-api": "down", "n-web": "degraded" },
      blastRadius: 1,
      down: ["n-api"],
      degraded: ["n-web"],
      graphRevision: "rev-fake-1",
    });
    expect(await screen.findByTestId("blast-radius-count")).toHaveTextContent("1");
    await waitFor(() => expect(screen.getByRole("combobox")).not.toBeDisabled());
    expect(screen.getByRole("button", { name: /Clear simulation/ })).not.toBeDisabled();

    // Re-select a DIFFERENT node → the new node's impact renders, never the stale one.
    await userEvent.selectOptions(screen.getByRole("combobox"), "n-api");
    await waitFor(() =>
      expect(fetchImpact).toHaveBeenLastCalledWith("atlas", "n-api", expect.anything()),
    );
    await waitFor(() =>
      expect(screen.getByLabelText("Blast-radius impact")).toHaveTextContent("n-api"),
    );
    // Not permanently disabled after the whole cycle.
    await waitFor(() => expect(screen.getByRole("combobox")).not.toBeDisabled());
  });
});
