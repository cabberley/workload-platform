import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError } from "../api/client";
import * as client from "../api/client";
import { FindingsView } from "./FindingsView";
import { makeFinding } from "../test/fixtures";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, fetchFindings: vi.fn() };
});

const fetchFindings = vi.mocked(client.fetchFindings);

beforeEach(() => {
  fetchFindings.mockReset();
});

describe("FindingsView", () => {
  it("lists findings with provenance", async () => {
    fetchFindings.mockResolvedValue([
      makeFinding({ id: "f1", title: "Alpha check", module: "quality_checks" }),
      makeFinding({ id: "f2", title: "Beta check", module: "aiops", passed: null }),
    ]);

    render(<FindingsView workload="atlas" />);

    expect(await screen.findByText("Alpha check")).toBeInTheDocument();
    expect(screen.getByText("Beta check")).toBeInTheDocument();
    // Provenance visible (pack@version).
    expect(screen.getAllByText(/rule\.tls\.fake@1\.2\.3/).length).toBeGreaterThan(0);
    // Tri-state: the null finding is surfaced as UNKNOWN, not a pass.
    expect(screen.getByText(/UNKNOWN/)).toBeInTheDocument();
  });

  it("filters by module", async () => {
    fetchFindings.mockResolvedValue([
      makeFinding({ id: "f1", title: "Alpha check", module: "quality_checks" }),
      makeFinding({ id: "f2", title: "Beta check", module: "aiops" }),
    ]);

    render(<FindingsView workload="atlas" />);
    await screen.findByText("Alpha check");

    await userEvent.selectOptions(screen.getByLabelText("Module"), "aiops");

    expect(screen.queryByText("Alpha check")).not.toBeInTheDocument();
    expect(screen.getByText("Beta check")).toBeInTheDocument();
  });

  it("shows an explicit empty state (not a verified pass)", async () => {
    fetchFindings.mockResolvedValue([]);
    render(<FindingsView workload="atlas" />);
    expect(await screen.findByText(/not a verified pass/)).toBeInTheDocument();
  });

  it("surfaces a 404 as a friendly empty read-model message", async () => {
    fetchFindings.mockRejectedValue(new ApiError(404, "404 Not Found"));
    render(<FindingsView workload="atlas" />);
    expect(await screen.findByText(/No findings read model/)).toBeInTheDocument();
  });

  it("fails closed on error — never an all-clear", async () => {
    fetchFindings.mockRejectedValue(new ApiError(500, "500 boom"));
    render(<FindingsView workload="atlas" />);
    await waitFor(() =>
      expect(screen.getByText(/not an all-clear/)).toBeInTheDocument(),
    );
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
});
