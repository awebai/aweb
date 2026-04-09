import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { APIClient } from "../src/api/client.js";

describe("APIClient URL construction", () => {
  const fetchMock = vi.fn<typeof fetch>();
  const auth = {
    did: "did:key:z6Mktest",
    signingKey: new Uint8Array(32).fill(1),
    teamAddress: "acme.com/backend",
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
          "X-AWID-Team-Certificate": "cert-header",
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

    const client = new APIClient(baseURL, auth);
    await client.openSSE(path);

    expect(fetchMock).toHaveBeenCalledWith(
      expectedURL,
      expect.objectContaining({
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
