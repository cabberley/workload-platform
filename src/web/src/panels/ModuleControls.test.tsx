import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import * as client from "../api/client";
import { ModuleControls } from "./ModuleControls";
import { makeModule } from "../test/fixtures";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, fetchModules: vi.fn() };
});

const fetchModules = vi.mocked(client.fetchModules);

beforeEach(() => {
  fetchModules.mockReset();
});

describe("ModuleControls", () => {
  it("lists modules with their enable state", async () => {
    fetchModules.mockResolvedValue([
      makeModule({ name: "discovery", displayName: "Discovery", enabled: true }),
      makeModule({ name: "aiops", displayName: "AIOps", enabled: false }),
    ]);
    render(<ModuleControls />);

    expect(await screen.findByText("Discovery")).toBeInTheDocument();
    expect(screen.getByText("AIOps")).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
    expect(screen.getByText(/1 of 2 modules enabled/)).toBeInTheDocument();
  });

  it("renders the enable/disable toggle as a DISABLED switch reflecting state (read-only)", async () => {
    fetchModules.mockResolvedValue([
      makeModule({ name: "discovery", displayName: "Discovery", enabled: true }),
      makeModule({ name: "aiops", displayName: "AIOps", enabled: false }),
    ]);
    render(<ModuleControls />);

    const switches = await screen.findAllByRole("switch");
    expect(switches).toHaveLength(2);
    // Every toggle is disabled — the console must NOT expose an unvalidated write path.
    for (const s of switches) {
      expect(s).toBeDisabled();
    }
    // aria-checked mirrors the manifest enabled state.
    expect(switches[0]).toHaveAttribute("aria-checked", "true");
    expect(switches[1]).toHaveAttribute("aria-checked", "false");
  });

  it("fails closed when the module read fails (state unknown, not all-clear)", async () => {
    fetchModules.mockRejectedValue(new Error("boom"));
    render(<ModuleControls />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/not an all-clear/i),
    );
  });

  it("shows an empty-state message when no modules are reported", async () => {
    fetchModules.mockResolvedValue([]);
    render(<ModuleControls />);
    expect(await screen.findByText(/No modules reported/)).toBeInTheDocument();
  });
});
