import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as client from "./api/client";
import { App } from "./App";
import { makeFinding, makeModule, makeRcaAdvisory } from "./test/fixtures";

// Mock the read-only API client so the SPA renders against synthetic read models (no network).
vi.mock("./api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api/client")>();
  return {
    ...actual,
    fetchWorkloads: vi.fn(),
    fetchModules: vi.fn(),
    fetchPackAssignments: vi.fn(),
    fetchFindings: vi.fn(),
    fetchRcaExplanations: vi.fn(),
  };
});

const fetchWorkloads = vi.mocked(client.fetchWorkloads);
const fetchModules = vi.mocked(client.fetchModules);
const fetchPackAssignments = vi.mocked(client.fetchPackAssignments);
const fetchFindings = vi.mocked(client.fetchFindings);
const fetchRcaExplanations = vi.mocked(client.fetchRcaExplanations);

beforeEach(() => {
  fetchWorkloads.mockResolvedValue(["atlas"]);
  fetchModules.mockResolvedValue([makeModule()]);
  fetchPackAssignments.mockResolvedValue([]);
  fetchFindings.mockResolvedValue([makeFinding({ id: "f1", title: "Alpha check" })]);
  fetchRcaExplanations.mockReset();
});

describe("App — grounded RCA advisory wiring (issue #54)", () => {
  it("fetches the advisory for the selected workload and renders it in the findings tab", async () => {
    fetchRcaExplanations.mockResolvedValue([
      makeRcaAdvisory({ advisory: "The evidence indicates node-fake-01 is saturated." }),
    ]);

    render(<App />);

    // Select the Findings tab once the default workload has loaded.
    const findingsTab = await screen.findByRole("button", { name: "Findings" });
    await userEvent.click(findingsTab);

    // The findings themselves render.
    expect(await screen.findByText("Alpha check")).toBeInTheDocument();
    // The fetched advisory + its AI-advisory labelling + cited evidence render alongside.
    expect(
      await screen.findByText(/The evidence indicates node-fake-01 is saturated\./),
    ).toBeInTheDocument();
    expect(screen.getByText(/AI ADVISORY/)).toBeInTheDocument();
    expect(screen.getByText("cpu_saturation_ratio")).toBeInTheDocument();
    // It was fetched for the selected workload.
    expect(fetchRcaExplanations).toHaveBeenCalledWith("atlas");
  });

  it("renders no advisory when the read path returns none (graceful, fail-closed)", async () => {
    fetchRcaExplanations.mockResolvedValue([]);

    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Findings" }));

    expect(await screen.findByText("Alpha check")).toBeInTheDocument();
    await waitFor(() => expect(fetchRcaExplanations).toHaveBeenCalledWith("atlas"));
    expect(screen.queryByText(/AI ADVISORY/)).not.toBeInTheDocument();
  });
});
