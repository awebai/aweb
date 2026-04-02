import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { APIClient } from "../src/api/client.js";

describe("APIClient URL construction", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test.each([
    [
      "http://localhost:8000",
      "/v1/messages/inbox",
      "http://localhost:8000/v1/messages/inbox",
    ],
    [
      "https://app.aweb.ai/api",
      "/v1/messages/inbox",
      "https://app.aweb.ai/api/v1/messages/inbox",
    ],
  ])("get() preserves the base path for %s", async (baseURL, path, expectedURL) => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new APIClient(baseURL, "test-key");
    await client.get(path);

    expect(fetchMock).toHaveBeenCalledWith(
      expectedURL,
      expect.objectContaining({
        method: "GET",
      }),
    );
  });

  test.each([
    [
      "http://localhost:8000",
      "/v1/events/stream",
      "http://localhost:8000/v1/events/stream",
    ],
    [
      "https://app.aweb.ai/api",
      "/v1/events/stream",
      "https://app.aweb.ai/api/v1/events/stream",
    ],
  ])("openSSE() preserves the base path for %s", async (baseURL, path, expectedURL) => {
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));

    const client = new APIClient(baseURL, "test-key");
    await client.openSSE(path);

    expect(fetchMock).toHaveBeenCalledWith(
      expectedURL,
      expect.objectContaining({
        headers: expect.objectContaining({
          Accept: "text/event-stream",
        }),
      }),
    );
  });
});
