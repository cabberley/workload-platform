import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { ApiError } from "../api/client";
import * as client from "../api/client";
import { DriftView } from "./DriftView";
import { makeDrift, makeFinding } from "../test/fixtures";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, fetchDrift: vi.fn() };
});

const fetchDrift = vi.mocked(client.fetchDrift);

beforeEach(() => {
  fetchDrift.mockReset();
});

describe("DriftView", () => {
  it("renders every section of the drift report", async () => {
    fetchDrift.mockResolvedValue(
      makeDrift({
        newFailures: [makeFinding({ id: "nf1", title: "Newly failing", passed: false })],
        recovered: [makeFinding({ id: "r1", title: "Recovered check", passed: true })],
        stillFailing: [makeFinding({ id: "sf1", title: "Still failing check", passed: false })],
        addedNodes: ["n-added"],
        removedNodes: ["n-removed"],
      }),
    );

    render(<DriftView workload="atlas" />);

    expect(await screen.findByText("Newly failing")).toBeInTheDocument();
    expect(screen.getByText("Recovered check")).toBeInTheDocument();
    expect(screen.getByText("Still failing check")).toBeInTheDocument();
    expect(screen.getByText("n-added")).toBeInTheDocument();
    expect(screen.getByText("n-removed")).toBeInTheDocument();
    // Section labels present.
    expect(screen.getByLabelText("New failures")).toBeInTheDocument();
    expect(screen.getByLabelText("Added nodes")).toBeInTheDocument();
    expect(screen.getByLabelText("Removed nodes")).toBeInTheDocument();
  });

  it("shows an explicit no-drift message when everything is empty", async () => {
    fetchDrift.mockResolvedValue(makeDrift());
    render(<DriftView workload="atlas" />);
    expect(await screen.findByText(/No drift detected/)).toBeInTheDocument();
  });

  it("surfaces a 404 as a friendly no-baseline message", async () => {
    fetchDrift.mockRejectedValue(new ApiError(404, "404 Not Found"));
    render(<DriftView workload="atlas" />);
    expect(await screen.findByText(/No drift baseline/)).toBeInTheDocument();
  });

  it("fails closed on error — never an all-clear", async () => {
    fetchDrift.mockRejectedValue(new ApiError(500, "500 boom"));
    render(<DriftView workload="atlas" />);
    await waitFor(() => expect(screen.getByText(/not an all-clear/)).toBeInTheDocument());
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
});
