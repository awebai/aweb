// How the emitter reads the activity route's answers (docs/agent-activity.md,
// "Emitters"): a local HTTP server returns each answer the route can give.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import * as ed from "@noble/ed25519";
import { APIClient } from "../src/api/client.js";
import { publishActivity } from "../src/activity/publish.js";
import { computeDIDKey } from "../src/identity/did.js";

const SEED = Uint8Array.from(Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"));
const BODY = { signed_payload: "eyJ2IjoxfQ", signature: "c2ln" };

let server: Server;
let reply: { status: number; body: string; headers?: Record<string, string> };
let received: { method?: string; url?: string; body: string; headers: Record<string, string | string[] | undefined> }[];

beforeEach(async () => {
  received = [];
  server = createServer((request, response) => {
    let body = "";
    request.on("data", chunk => (body += chunk));
    request.on("end", () => {
      received.push({ method: request.method, url: request.url, body, headers: request.headers });
      response.writeHead(reply.status, { "Content-Type": "application/json", ...(reply.headers ?? {}) });
      response.end(reply.body);
    });
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
});
afterEach(async () => {
  await new Promise<void>(resolve => server.close(() => resolve()));
});

function client(): APIClient {
  const { port } = server.address() as AddressInfo;
  return new APIClient(`http://127.0.0.1:${port}`, {
    did: computeDIDKey(ed.getPublicKey(SEED)),
    stableID: "",
    signingKey: SEED,
    teamID: "default:acme.aweb.ai",
    teamCertificateHeader: "certificate",
  });
}

describe("publishActivity", () => {
  test("202 with no body is accepted, and the request is a team-authenticated POST", async () => {
    reply = { status: 202, body: "" };
    expect(await publishActivity(client(), BODY)).toEqual({ kind: "accepted" });
    expect(received).toHaveLength(1);
    expect(received[0].method).toBe("POST");
    expect(received[0].url).toBe("/v1/agents/me/activity");
    expect(JSON.parse(received[0].body)).toEqual(BODY);
    expect(received[0].headers["x-awid-team-certificate"]).toBe("certificate");
  });

  test("429 is rate limited for Retry-After seconds", async () => {
    reply = { status: 429, body: '{"detail":"rate_limited: too many"}', headers: { "Retry-After": "3" } };
    expect(await publishActivity(client(), BODY)).toEqual({ kind: "rate_limited", retryAfterSeconds: 3 });
  });

  test("429 without a usable Retry-After waits one rate window", async () => {
    reply = { status: 429, body: '{"detail":"rate_limited: too many"}', headers: { "Retry-After": "soon" } };
    expect(await publishActivity(client(), BODY)).toEqual({ kind: "rate_limited", retryAfterSeconds: 5 });
  });

  test("the shared resource 404 is a refused session", async () => {
    reply = { status: 404, body: '{"detail":"Not found"}' };
    expect(await publishActivity(client(), BODY)).toEqual({ kind: "session_refused" });
  });

  test.each([
    ["the framework's absent route", '{"detail":"Not Found"}'],
    ["a proxy page", "<html>404</html>"],
    ["an empty body", ""],
  ])("any other 404 (%s) is an absent route", async (_name, body) => {
    reply = { status: 404, body };
    expect(await publishActivity(client(), BODY)).toEqual({ kind: "route_absent" });
  });

  test.each([[422], [403], [500], [503]])("%i is a failed publish", async (status) => {
    reply = { status, body: '{"detail":"x"}' };
    expect(await publishActivity(client(), BODY)).toEqual({ kind: "failed" });
  });

  test("an unreachable server is a failed publish", async () => {
    const unreachable = client();
    await new Promise<void>(resolve => server.close(() => resolve()));
    server = createServer();
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    expect(await publishActivity(unreachable, BODY)).toEqual({ kind: "failed" });
  });
});
