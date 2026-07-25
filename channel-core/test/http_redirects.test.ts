import { createServer, type RequestListener } from "node:http";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, test, vi } from "vitest";
import { APIClient, RegistryResolver } from "../src/index.js";

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
