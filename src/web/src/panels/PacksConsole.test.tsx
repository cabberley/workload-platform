import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import * as client from "../api/client";
import { PacksConsole } from "./PacksConsole";
import { makePack } from "../test/fixtures";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, fetchPacks: vi.fn() };
});

const fetchPacks = vi.mocked(client.fetchPacks);

beforeEach(() => {
  fetchPacks.mockReset();
});

describe("PacksConsole", () => {
  it("lists published pack versions with signed status", async () => {
    fetchPacks.mockResolvedValue([
      makePack({ id: "rule.tls.fake", version: "1.2.0", signed: true }),
      makePack({ id: "wl.atlas.fake", version: "2.0.0", type: "workload", signed: false }),
    ]);
    render(<PacksConsole workload="atlas" />);

    expect(await screen.findByText("rule.tls.fake")).toBeInTheDocument();
    expect(screen.getByText("wl.atlas.fake")).toBeInTheDocument();
    expect(screen.getByText("signed")).toBeInTheDocument();
    expect(screen.getByText("unsigned")).toBeInTheDocument();
  });

  it("treats an empty catalogue as fail-closed (not an all-clear)", async () => {
    fetchPacks.mockResolvedValue([]);
    render(<PacksConsole workload="atlas" />);
    expect(await screen.findByText(/No pack versions published/)).toBeInTheDocument();
  });

  it("fails closed when the registry read fails", async () => {
    fetchPacks.mockRejectedValue(new Error("boom"));
    render(<PacksConsole workload="atlas" />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/not an all-clear/i),
    );
  });

  it("keeps assignment READ-ONLY: current assignment unavailable and Assign disabled", async () => {
    fetchPacks.mockResolvedValue([makePack({ signed: true })]);
    render(<PacksConsole workload="atlas" />);

    expect(await screen.findByText(/current assignment:/)).toBeInTheDocument();
    // Never rendered as "none"/all-clear — explicitly unavailable.
    expect(screen.getByText(/unavailable \(no assignment backend/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Assign" })).toBeDisabled();
  });

  it("offers only SIGNED versions as assignment candidates (fail closed)", async () => {
    fetchPacks.mockResolvedValue([
      makePack({ id: "rule.signed.fake", version: "1.0.0", signed: true }),
      makePack({ id: "rule.unsigned.fake", version: "9.9.9", signed: false }),
    ]);
    render(<PacksConsole workload="atlas" />);

    const select = (await screen.findByLabelText(/Signed version:/)) as HTMLSelectElement;
    const options = within(select).getAllByRole("option");
    const values = options.map((o) => (o as HTMLOptionElement).value);
    expect(values).toContain("rule.signed.fake@1.0.0");
    // Unsigned version must NOT be an assignable option.
    expect(values).not.toContain("rule.unsigned.fake@9.9.9");
  });

  it("prompts to select a workload when none is selected", async () => {
    fetchPacks.mockResolvedValue([makePack()]);
    render(<PacksConsole workload={null} />);
    expect(await screen.findByText(/Select a workload above/)).toBeInTheDocument();
  });
});
