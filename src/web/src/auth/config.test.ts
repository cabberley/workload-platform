import { describe, it, expect } from "vitest";
import { readAuthConfig } from "./config";

describe("readAuthConfig (config-driven, keyless)", () => {
  it("returns null when nothing is configured (local/no-auth path)", () => {
    expect(readAuthConfig({})).toBeNull();
  });

  it("returns null when the client id is missing", () => {
    expect(
      readAuthConfig({ VITE_AUTH_TENANT_ID: "t1", VITE_AUTH_API_SCOPE: "api://a/.default" })
    ).toBeNull();
  });

  it("returns null when the API scope is missing", () => {
    expect(
      readAuthConfig({ VITE_AUTH_CLIENT_ID: "c1", VITE_AUTH_TENANT_ID: "t1" })
    ).toBeNull();
  });

  it("returns null when neither authority nor tenant id is present", () => {
    expect(
      readAuthConfig({ VITE_AUTH_CLIENT_ID: "c1", VITE_AUTH_API_SCOPE: "api://a/.default" })
    ).toBeNull();
  });

  it("derives the canonical authority from the tenant id", () => {
    const config = readAuthConfig({
      VITE_AUTH_CLIENT_ID: "c1",
      VITE_AUTH_TENANT_ID: "tenant-guid",
      VITE_AUTH_API_SCOPE: "api://a/.default",
    });
    expect(config).toEqual({
      clientId: "c1",
      authority: "https://login.microsoftonline.com/tenant-guid",
      apiScope: "api://a/.default",
    });
  });

  it("prefers an explicit authority over the tenant-derived one", () => {
    const config = readAuthConfig({
      VITE_AUTH_CLIENT_ID: "c1",
      VITE_AUTH_TENANT_ID: "tenant-guid",
      VITE_AUTH_AUTHORITY: "https://login.microsoftonline.com/explicit",
      VITE_AUTH_API_SCOPE: "api://a/.default",
    });
    expect(config?.authority).toBe("https://login.microsoftonline.com/explicit");
  });

  it("trims surrounding whitespace and never reads a secret field", () => {
    const config = readAuthConfig({
      VITE_AUTH_CLIENT_ID: "  c1  ",
      VITE_AUTH_TENANT_ID: "  tenant-guid  ",
      VITE_AUTH_API_SCOPE: "  api://a/.default  ",
    });
    expect(config).toEqual({
      clientId: "c1",
      authority: "https://login.microsoftonline.com/tenant-guid",
      apiScope: "api://a/.default",
    });
  });
});
