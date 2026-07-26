import { createServer, type RequestListener } from "node:http";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, test, vi } from "vitest";
import { APIClient, RegistryResolver } from "../src/index.js";
import { readBoundedResponse } from "../src/api/response.js";

const openServers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(openServers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  })));
});

async function listen(handler: RequestListener): Promise<string> {
  const server = createServer(handler);
  openServers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server has no TCP address");
  return `http://127.0.0.1:${address.port}`;
}

async function redirectPair(): Promise<{ sourceURL: string; targetHits: () => number }> {
  let hits = 0;
  const targetURL = await listen((_request, response) => {
    hits += 1;
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end("{}");
  });
  const sourceURL = await listen((request, response) => {
    response.writeHead(307, { Location: `${targetURL}${request.url || "/"}` });
    response.end();
  });
  return { sourceURL, targetHits: () => hits };
}

const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

describe("trust requests reject redirects", () => {
  const auth = {
    did: "did:key:z6Mktest",
    stableID: "did:aw:test",
    signingKey: new Uint8Array(32).fill(1),
    teamID: "backend:acme.com",
    teamCertificateHeader: "secret-cert-header",
  };

  test("standard API requests never contact the redirect target", async () => {
    const pair = await redirectPair();
    const client = new APIClient(pair.sourceURL, auth);

    await expect(client.get("/v1/teams/backend%3Aacme.com/agents/alice")).rejects.toThrow();
    expect(pair.targetHits()).toBe(0);
  });

  test("SSE handshakes never contact the redirect target", async () => {
    const pair = await redirectPair();
    const client = new APIClient(pair.sourceURL, auth);

    await expect(client.openSSE("/v1/events/stream", new AbortController().signal)).rejects.toThrow();
    expect(pair.targetHits()).toBe(0);
  });

  test("registry lookups never contact the redirect target", async () => {
    const pair = await redirectPair();
    const notFound = Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    const resolver = new RegistryResolver(fetch, async () => { throw notFound; }, undefined, {
      fallbackRegistryURL: pair.sourceURL,
    });

    await expect(resolver.resolveAddressIdentity("example.com/alice")).rejects.toThrow();
    expect(pair.targetHits()).toBe(0);
  });
});

describe("trust response bounds", () => {
  const auth = {
    did: "did:key:z6Mktest",
    stableID: "did:aw:test",
    signingKey: new Uint8Array(32).fill(1),
    teamID: "backend:acme.com",
    teamCertificateHeader: "secret-cert-header",
  };

  test("standard API accepts exactly the limit and rejects one trailing byte", async () => {
    const serverURL = await listen((request, response) => {
      const size = request.url === "/exact" ? MAX_RESPONSE_BYTES : MAX_RESPONSE_BYTES + 1;
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(`{}${" ".repeat(size - 2)}`);
    });
    const client = new APIClient(serverURL, auth);

    await expect(client.get("/exact")).resolves.toEqual({});
    await expect(client.get("/oversize")).rejects.toThrow(/maximum|size|large|limit/i);
  });

  test("a declared length over the limit is refused before the body is read", async () => {
    let pulled = 0;
    let cancelled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new Uint8Array(1024));
      },
      cancel() {
        cancelled += 1;
      },
    });
    const response = new Response(body, {
      headers: { "Content-Length": String(MAX_RESPONSE_BYTES + 1) },
    });

    await expect(readBoundedResponse(response, MAX_RESPONSE_BYTES)).rejects.toThrow(
      /maximum|size|large|limit/i,
    );
    // The accumulating loop would also refuse this body, so not reading it at
    // all is what distinguishes the declared-length pre-check from that check.
    expect(pulled).toBe(0);
    expect(cancelled).toBe(1);
  });

  test("a declared length exactly at the limit is read rather than refused", async () => {
    const content = `{}${" ".repeat(MAX_RESPONSE_BYTES - 2)}`;
    const response = new Response(content, {
      headers: { "Content-Length": String(MAX_RESPONSE_BYTES) },
    });

    await expect(readBoundedResponse(response, MAX_RESPONSE_BYTES)).resolves.toHaveLength(
      MAX_RESPONSE_BYTES,
    );
  });

  test.each([
    { name: "trailing whitespace", suffix: " \r\n\t", shouldSucceed: true },
    { name: "a second document", suffix: "\n{}", shouldSucceed: false },
  ])("standard API handles $name strictly", async ({ suffix, shouldSucceed }) => {
    const serverURL = await listen((_request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(`{}${suffix}`);
    });
    const client = new APIClient(serverURL, auth);

    const request = client.get("/strict-json");
    if (shouldSucceed) {
      await expect(request).resolves.toEqual({});
    } else {
      await expect(request).rejects.toThrow();
    }
  });

  test.each([
    { name: "trailing whitespace", suffix: " \r\n\t", shouldSucceed: true },
    { name: "a second document", suffix: "\n{}", shouldSucceed: false },
  ])("registry resolver handles $name strictly", async ({ suffix, shouldSucceed }) => {
    const didKey = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
    const serverURL = await listen((request, response) => {
      const body = request.url?.includes("/addresses/")
        ? {
            address_id: "addr-1",
            domain: "example.com",
            name: "alice",
            did_aw: "did:aw:test",
            current_did_key: didKey,
            created_at: "2026-07-25T00:00:00Z",
          }
        : { did_aw: "did:aw:test", current_did_key: didKey };
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(`${JSON.stringify(body)}${suffix}`);
    });
    const notFound = Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    const resolver = new RegistryResolver(fetch, async () => { throw notFound; }, undefined, {
      fallbackRegistryURL: serverURL,
    });

    const request = resolver.resolveAddressIdentity("example.com/alice");
    if (shouldSucceed) {
      await expect(request).resolves.toEqual({ did: didKey, stableID: "did:aw:test" });
    } else {
      await expect(request).rejects.toThrow();
    }
  });

  test("standard API rejects a decompressed response over the limit", async () => {
    const content = gzipSync(`{}${" ".repeat(MAX_RESPONSE_BYTES - 1)}`);
    const serverURL = await listen((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "Content-Length": String(content.byteLength),
      });
      response.end(content);
    });
    const client = new APIClient(serverURL, auth);

    await expect(client.get("/gzip-bomb")).rejects.toThrow(/maximum|size|large|limit/i);
  });

  test("bounded reads cancel and unlock every repeated oversize response", async () => {
    const attempts = 32;
    let cancellations = 0;

    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(new Uint8Array(2048));
        },
        cancel() {
          cancellations += 1;
        },
      });
      await expect(readBoundedResponse(new Response(body), 1024)).rejects.toThrow(
        /maximum|size|large|limit/i,
      );
      expect(body.locked).toBe(false);
    }

    expect(cancellations).toBe(attempts);
  });

  test("SSE errors stop reading at the diagnostic limit", async () => {
    const chunkSize = 8192;
    let bytesProduced = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (bytesProduced >= 1024 * 1024) {
          controller.close();
          return;
        }
        bytesProduced += chunkSize;
        controller.enqueue(new Uint8Array(chunkSize).fill(120));
      },
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(body, { status: 500 })));
    const client = new APIClient("https://app.example", auth);

    await expect(client.openSSE("/v1/events/stream", new AbortController().signal)).rejects.toThrow();
    expect(bytesProduced).toBeLessThanOrEqual(64 * 1024 + 2 * chunkSize);
  });

  test("registry resolver rejects the first oversize trust response", async () => {
    let requests = 0;
    const serverURL = await listen((_request, response) => {
      requests += 1;
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(`{}${" ".repeat(MAX_RESPONSE_BYTES - 1)}`);
    });
    const notFound = Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    const resolver = new RegistryResolver(fetch, async () => { throw notFound; }, undefined, {
      fallbackRegistryURL: serverURL,
    });

    await expect(resolver.resolveAddressIdentity("example.com/alice")).rejects.toThrow(/maximum|size|large|limit/i);
    expect(requests).toBe(1);
  });
});
