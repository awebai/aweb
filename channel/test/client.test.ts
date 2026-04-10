import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { APIClient } from "../src/api/client.js";

describe("APIClient URL construction", () => {
  const fetchMock = vi.fn<typeof fetch>();
  const auth = {
    did: "did:key:z6Mktest",
    stableID: "did:aw:test",
    signingKey: new Uint8Array(32).fill(1),
    teamID: "backend:acme.com",
    teamCertificateHeader: "cert-header",
  };

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

    const client = new APIClient(baseURL, auth);
    await client.get(path);

    expect(fetchMock).toHaveBeenCalledWith(
      expectedURL,
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: expect.stringMatching(/^DIDKey did:key:z6Mktest /),
          "X-AWEB-Timestamp": expect.any(String),
          "X-AWEB-DID-AW": "did:aw:test",
        }),
      }),
    );
  });

  test("chat history uses identity-scoped auth", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new APIClient("http://localhost:8000", auth);
    await client.get("/v1/chat/sessions/sess-1/messages?limit=10");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/v1/chat/sessions/sess-1/messages?limit=10",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: expect.stringMatching(/^DIDKey did:key:z6Mktest /),
          "X-AWEB-Timestamp": expect.any(String),
          "X-AWEB-DID-AW": "did:aw:test",
        }),
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
    const controller = new AbortController();

    const client = new APIClient(baseURL, auth);
    await client.openSSE(path, controller.signal);

    expect(fetchMock).toHaveBeenCalledWith(
      expectedURL,
      expect.objectContaining({
        signal: controller.signal,
        headers: expect.objectContaining({
          Authorization: expect.stringMatching(/^DIDKey did:key:z6Mktest /),
          Accept: "text/event-stream",
          "X-AWEB-Timestamp": expect.any(String),
          "X-AWID-Team-Certificate": "cert-header",
        }),
      }),
    );
  });
});
