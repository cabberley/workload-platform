import { afterEach, describe, it, expect, vi } from "vitest";
import { fetchModules, setAuthTokenProvider } from "./client";

function stubFetchOk(): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn(async () =>
    new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } })
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function headersOf(fetchMock: ReturnType<typeof vi.fn>): Record<string, string> {
  const init = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined;
  return (init?.headers as Record<string, string>) ?? {};
}

afterEach(() => {
  setAuthTokenProvider(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("api client bearer-token seam (keyless)", () => {
  it("sends no Authorization header when no provider is registered", async () => {
    const fetchMock = stubFetchOk();
    await fetchModules();
    expect(headersOf(fetchMock).Authorization).toBeUndefined();
  });

  it("attaches a fresh bearer token from the registered provider", async () => {
    const fetchMock = stubFetchOk();
    setAuthTokenProvider(async () => "tok-123");
    await fetchModules();
    expect(headersOf(fetchMock).Authorization).toBe("Bearer tok-123");
  });

  it("omits the header (fail-closed) when the provider returns null", async () => {
    const fetchMock = stubFetchOk();
    setAuthTokenProvider(async () => null);
    await fetchModules();
    expect(headersOf(fetchMock).Authorization).toBeUndefined();
  });

  it("acquires the token per request, not once at registration", async () => {
    const fetchMock = stubFetchOk();
    const provider = vi.fn(async () => "tok-abc");
    setAuthTokenProvider(provider);
    await fetchModules();
    await fetchModules();
    expect(provider).toHaveBeenCalledTimes(2);
  });
});
