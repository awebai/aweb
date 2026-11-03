import { createServer } from "node:http";
import { afterEach, expect, test, vi } from "vitest";
import { APIClient, startPresenceHeartbeat } from "../src/index.js";

afterEach(() => vi.useRealTimers());

test.each(["team", "grant"] as const)("presence timer sends real %s-auth HTTP heartbeats until abort", async (authMode) => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  let count = 0;
  let arrived: () => void = () => {};
  const arrival = new Promise<void>((resolve) => { arrived = resolve; });
  const server = createServer((req, res) => {
    expect(req.method).toBe("POST");
    expect(req.url).toBe("/v1/agents/heartbeat");
    expect(req.headers.authorization).toMatch(authMode === "grant" ? /^AWEB-Grant DIDKey / : /^DIDKey /);
    if (authMode === "team") expect(req.headers["x-awid-team-certificate"]).toBe("presence-cert");
    else expect(req.headers["x-aweb-grant-id"]).toBe("presence-grant");
    count++;
    res.writeHead(200, { "content-type": "application/json" }); res.end("{}");
    arrived();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("server did not bind");
  const client = new APIClient(`http://127.0.0.1:${address.port}`, {
    did: "did:key:z6Mktest", stableID: "did:aw:test", signingKey: new Uint8Array(32).fill(1),
    teamID: "dev:example.com", teamCertificateHeader: "presence-cert", authMode, grantID: "presence-grant",
  });
  const abort = new AbortController();
  const stop = startPresenceHeartbeat(client, abort.signal);
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    vi.advanceTimersByTime(299999);
    expect(count).toBe(0);
    vi.advanceTimersByTime(1);
    await Promise.race([arrival, new Promise((_, reject) => {
      deadline = setTimeout(() => reject(new Error("heartbeat did not reach HTTP server")), 2000);
    })]);
    expect(count).toBe(1);
    abort.abort();
    vi.advanceTimersByTime(600000);
    expect(vi.getTimerCount()).toBe(0);
    expect(count).toBe(1);
  } finally {
    abort.abort(); stop();
    clearTimeout(deadline);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}, 3000);

test("a failed heartbeat retries next tick and abort cancels a stalled request", async () => {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  let count = 0;
  let failed: () => void = () => {}, stalled: () => void = () => {}, closed: () => void = () => {};
  const failure = new Promise<void>((r) => { failed = r; });
  const arrival = new Promise<void>((r) => { stalled = r; });
  const disconnect = new Promise<void>((r) => { closed = r; });
  const server = createServer((_req, res) => {
    count++;
    if (count === 1) { res.writeHead(503); res.end("unavailable"); return; }
    res.once("close", closed);
    stalled();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no address");
  const abort = new AbortController();
  const stop = startPresenceHeartbeat(new APIClient(`http://127.0.0.1:${address.port}`, {
    did:"did:key:z6Mktest", stableID:"", signingKey:new Uint8Array(32).fill(1), teamID:"dev:example.com", teamCertificateHeader:"cert",
  }), abort.signal, failed);
  try {
    vi.advanceTimersByTime(300000);
    await failure;
    vi.advanceTimersByTime(300000);
    await arrival;
    abort.abort();
    await disconnect;
    expect(count).toBe(2);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    stop(); server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}, 3000);
