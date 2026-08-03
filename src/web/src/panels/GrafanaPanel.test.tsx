import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { GrafanaPanel } from "./GrafanaPanel";

// Clearly-fake, synthetic URLs. NOT real endpoints and NOT tokens.
const FAKE_GRAFANA_URL = "https://grafana.example.invalid/";
const FAKE_PANEL_URL = "https://grafana.example.invalid/d-solo/wp-workload-health?panelId=1";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("GrafanaPanel", () => {
  it("renders the documented placeholder (fail-closed) when nothing is configured", () => {
    vi.stubEnv("VITE_GRAFANA_URL", "");
    vi.stubEnv("VITE_GRAFANA_PANEL_URL", "");

    const { container } = render(<GrafanaPanel />);

    expect(screen.getByText(/No telemetry surface configured/)).toBeInTheDocument();
    expect(screen.getByText("VITE_GRAFANA_URL")).toBeInTheDocument();
    // Fail-closed: nothing embedded and no live link.
    expect(container.querySelector("iframe")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    // No configured URL or any real endpoint leaks into the placeholder DOM.
    const html = container.innerHTML;
    expect(html).not.toContain(FAKE_GRAFANA_URL);
    expect(html).not.toContain(FAKE_PANEL_URL);
    expect(html).not.toMatch(/src=|href=|https?:\/\//i);
  });

  it("renders a keyless deep-link (new tab, noopener) by default when VITE_GRAFANA_URL is set", () => {
    vi.stubEnv("VITE_GRAFANA_URL", FAKE_GRAFANA_URL);
    vi.stubEnv("VITE_GRAFANA_PANEL_URL", "");

    const { container } = render(<GrafanaPanel />);

    const link = screen.getByRole("link", { name: /Open dashboards in Azure Managed Grafana/i });
    expect(link).toBeInTheDocument();
    expect(link.getAttribute("href")).toBe(FAKE_GRAFANA_URL);
    expect(link.getAttribute("target")).toBe("_blank");
    expect(link.getAttribute("rel")).toBe("noopener noreferrer");
    // Default path does NOT embed an iframe.
    expect(container.querySelector("iframe")).toBeNull();
    expect(screen.queryByText(/No telemetry surface configured/)).toBeNull();
    // No token leaks.
    expect(container.innerHTML).not.toMatch(/api[_-]?key|token|bearer|password|secret/i);
  });

  it("renders the OPTIONAL sandboxed iframe with safe attributes when VITE_GRAFANA_PANEL_URL is set", () => {
    vi.stubEnv("VITE_GRAFANA_URL", FAKE_GRAFANA_URL);
    vi.stubEnv("VITE_GRAFANA_PANEL_URL", FAKE_PANEL_URL);

    render(<GrafanaPanel />);

    const iframe = screen.getByTitle("Embedded Managed Grafana panel") as HTMLIFrameElement;
    expect(iframe).toBeInTheDocument();
    expect(iframe.getAttribute("src")).toBe(FAKE_PANEL_URL);
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts allow-same-origin");
    expect(iframe.getAttribute("referrerpolicy")).toBe("no-referrer");
    // Panel path takes precedence over the deep-link and the placeholder.
    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.queryByText(/No telemetry surface configured/)).toBeNull();
    // The panel URL carries no token/secret.
    expect(FAKE_PANEL_URL).not.toMatch(/api[_-]?key|token|bearer|password|secret/i);
  });
});
