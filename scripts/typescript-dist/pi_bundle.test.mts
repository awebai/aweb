// Behaviour of the built Pi extension bundle named by AWEB_PI_DIST. Run by
// scripts/test-typescript-dist-freshness.sh against the production build and
// against bundles rebuilt from a mutated source.
//
// The stream cases host the bundle's default export as Pi does, against an
// event server on 127.0.0.1 owned by the test. node:test mock timers drive the
// bundle's setTimeout and Date; the sockets stay real.
import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { delimiter, join } from "node:path";
import test, { type TestContext } from "node:test";
import { pathToFileURL } from "node:url";

import {
  genesisKeyAnswer,
  json,
  startLoopbackServer,
  stableIDOf,
  temporaryDirectory,
  writeSigningKey,
  writeTeamCertificate,
  writeTeamState,
  writeTestPrincipal,
  writeWorkspaceBinding,
} from "../../channel-core/test/helpers/dist_fixture.ts";

const distPath = process.env.AWEB_PI_DIST;
if (!distPath) throw new Error("AWEB_PI_DIST must name the built Pi extension bundle");

// The bundle resolves ~/.config/aw paths at module load, so the isolated home
// and environment are in place before it is imported.
process.env.HOME = temporaryDirectory("aweb-pi-dist-home-");
for (const name of ["AWEB_IDENTITY_HOME", "AWEB_DELIVERY", "AWID_REGISTRY_URL", "AWEB_URL"]) delete process.env[name];
// The fixture aw answers the one bootstrap command the extension runs.
const bin = temporaryDirectory("aweb-pi-dist-bin-");
writeFileSync(join(bin, "aw"), '#!/bin/sh\n[ "$1 $2" = "workspace status" ] || exit 64\nexit 0\n');
chmodSync(join(bin, "aw"), 0o755);
process.env.PATH = `${bin}${delimiter}${process.env.PATH || ""}`;

const bundle = await import(pathToFileURL(distPath).href);
const realSetTimeout = globalThis.setTimeout;

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => { realSetTimeout(resolve, ms); });
}

/** Wait in real time for a condition the bundle brings about over its sockets. */
async function eventually(condition: () => boolean, message: string, ms = 3_000): Promise<void> {
  // performance.now is real time; Date is the fake clock while timers are mocked.
  const until = performance.now() + ms;
  while (!condition()) {
    if (performance.now() > until) assert.fail(message);
    await pause(5);
  }
}

test("Pi takes the certificate's stable_id over identity.yaml's", async () => {
  async function loadStableID(identityStableID: string): Promise<string> {
    const workdir = temporaryDirectory("aweb-pi-dist-config-");
    const awDir = join(workdir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(23);
    const certPath = "team-certs/backend__acme.com.pem";
    const { did } = await writeTeamCertificate(join(awDir, certPath), seed, {
      team_id: "backend:acme.com", alias: "alice", member_did_aw: "did:aw:cert",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);
    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", certPath);
    writeTeamState(awDir, "backend:acme.com", "alice", certPath);
    writeFileSync(join(awDir, "identity.yaml"), `did: ${did}\nstable_id: ${identityStableID}\n`);
    return (await bundle.loadChannelConfig(workdir)).stableID;
  }
  assert.equal(await loadStableID("did:aw:cert"), "did:aw:cert", "a consistent workspace did not load");
  assert.equal(
    await loadStableID("did:aw:stale"), "did:aw:cert",
    "S4b: the certificate's stable_id must win over identity.yaml's",
  );
});

test("Pi refuses a genesis whose key does not derive its did:aw", async () => {
  async function verify(stableID: string) {
    const signer = new Uint8Array(32).fill(61);
    const answer = genesisKeyAnswer(signer, stableID);
    const registry = await startLoopbackServer((request, response) => {
      if (request.url === "/v1/namespaces/aweb.test/addresses/alice") {
        json(response, 200, {
          address_id: "address-alice", domain: "aweb.test", name: "alice",
          did_aw: stableID, current_did_key: answer.current_did_key, created_at: "2026-07-26T00:00:00Z",
        });
      } else if (request.url === `/v1/did/${stableID}/key`) {
        json(response, 200, answer);
      } else {
        json(response, 404, { detail: "not found" });
      }
    });
    try {
      const resolver = bundle.createPiRegistryResolver({ registryURL: registry.url, address: "aweb.test/alice" });
      return await resolver.verifyStableIdentity("aweb.test/alice", stableID, answer.current_did_key);
    } finally {
      await registry.close();
    }
  }
  const valid = await verify(stableIDOf(new Uint8Array(32).fill(61)));
  assert.equal(valid.outcome, "OK_VERIFIED", `valid genesis was not verified: ${JSON.stringify(valid)}`);
  const forged = await verify(stableIDOf(new Uint8Array(32).fill(62)));
  assert.deepEqual(
    { outcome: forged.outcome, error: forged.error },
    { outcome: "HARD_ERROR", error: "did:aw not derived from genesis key" },
    "S4a: the genesis key must derive the did:aw",
  );
});

interface StreamRequest {
  deadline: number;
  response: ServerResponse;
  closed: boolean;
  /** Listeners on the session AbortSignal when the request arrived. */
  sessionListeners: number;
}

type StreamAnswer = (request: StreamRequest, incoming: IncomingMessage) => void;

/**
 * Start a Pi session from the bundle's default export against an owned event
 * server. `answer` decides each stream request's response.
 */
async function startPiSession(t: TestContext, answer: StreamAnswer) {
  const workdir = temporaryDirectory("aweb-pi-dist-session-");
  const identityHome = join(workdir, ".aw");
  await writeTestPrincipal(identityHome, { alias: "pi-dist", seedByte: 71, teamID: "dist:aweb.test" });

  const streams: StreamRequest[] = [];
  const statuses: string[] = [];
  // The bundle reports stream states on console.warn; they are this test's evidence.
  const logs: string[] = [];
  const consoleWarn = console.warn;
  console.warn = (...parts: unknown[]) => { logs.push(parts.join(" ")); };
  let sessionSignal: AbortSignal | undefined;
  const server = await startLoopbackServer((incoming, response) => {
    const url = new URL(incoming.url || "/", "http://127.0.0.1");
    if (url.pathname === "/v1/agents/heartbeat") {
      json(response, 200, {});
      return;
    }
    if (url.pathname !== "/v1/events/stream") {
      json(response, 404, { detail: "not served by this fixture" });
      return;
    }
    const request: StreamRequest = {
      deadline: Date.parse(url.searchParams.get("deadline") || ""),
      response,
      closed: false,
      sessionListeners: sessionSignal ? getEventListeners(sessionSignal, "abort").length : -1,
    };
    response.on("close", () => { request.closed = true; });
    streams.push(request);
    answer(request, incoming);
  });
  const workspace = join(identityHome, "workspace.yaml");
  writeFileSync(workspace, readFileSync(workspace, "utf8").replace(/^aweb_url: .*$/m, `aweb_url: ${server.url}`));

  const handlers = new Map<string, (event: unknown, ctx: unknown) => Promise<void> | void>();
  const pi = {
    on(event: string, handler: (event: unknown, ctx: unknown) => Promise<void> | void) { handlers.set(event, handler); },
    sendMessage() {},
  };
  const ctx = {
    cwd: workdir,
    hasUI: true,
    ui: {
      theme: { fg: (_kind: string, text: string) => text },
      setStatus: (_key: string, value: string) => { statuses.push(value); },
      notify: () => {},
    },
  };

  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.now() });
  bundle.default(pi);
  // The session's AbortController is the first one session_start constructs.
  const NativeAbortController = globalThis.AbortController;
  globalThis.AbortController = class extends NativeAbortController {
    constructor() {
      super();
      sessionSignal = this.signal;
      globalThis.AbortController = NativeAbortController;
    }
  };
  try {
    await handlers.get("session_start")!({}, ctx);
  } finally {
    globalThis.AbortController = NativeAbortController;
  }
  assert.ok(sessionSignal, "session_start constructed no AbortController");

  return {
    streams,
    statuses,
    logs,
    identityHome,
    /** Shut the session down, then the server, and wait for every stream socket to close. */
    async close() {
      t.mock.timers.reset();
      try {
        await handlers.get("session_shutdown")!({}, ctx);
        await server.close();
      } finally {
        console.warn = consoleWarn;
      }
      await eventually(() => streams.every((stream) => stream.closed), "a stream socket outlived the session");
    },
  };
}

/** The receive receipt's heartbeat time, written when the bundle reads stream bytes. */
function receiptHeartbeat(identityHome: string): number | undefined {
  try {
    return Date.parse(JSON.parse(readFileSync(join(identityHome, "receive", "stream.json"), "utf8")).heartbeat_at);
  } catch {
    return undefined;
  }
}

/** Write a heartbeat comment and wait until the bundle has read it at the current fake time. */
async function beat(session: { identityHome: string }, stream: StreamRequest): Promise<void> {
  stream.response.write(": heartbeat\n\n");
  const now = Date.now();
  await eventually(() => receiptHeartbeat(session.identityHome) === now, "the bundle did not read a heartbeat");
}

function keepOpen(request: StreamRequest): void {
  request.response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  request.response.write(": connected\n\n");
}

test("Pi closes a stream at its requested deadline and reconnects", async (t) => {
  const session = await startPiSession(t, keepOpen);
  try {
    await eventually(() => session.streams.length === 1, "the bundle never opened the event stream");
    const first = session.streams[0];
    assert.ok(Number.isFinite(first.deadline), "the stream request carried no deadline");
    await eventually(() => receiptHeartbeat(session.identityHome) !== undefined, "the stream was never confirmed live");
    // Heartbeats keep the stream live up to one millisecond before its deadline.
    while (first.deadline - Date.now() > 30_000) {
      t.mock.timers.tick(30_000);
      await beat(session, first);
    }
    t.mock.timers.tick(first.deadline - Date.now() - 1);
    await pause(50);
    assert.equal(first.closed, false, "the stream closed before its deadline");
    assert.equal(session.streams.length, 1);
    t.mock.timers.tick(1);
    await eventually(() => first.closed, "S4c: the stream must close at its deadline");
    await eventually(() => session.streams.length === 2, "the bundle did not reconnect after the planned close");
  } finally {
    await session.close();
  }
});

test("Pi gives up on a stream silent for 75 seconds and reconnects after the retry delay", async (t) => {
  const session = await startPiSession(t, keepOpen);
  try {
    await eventually(() => session.streams.length === 1, "the bundle never opened the event stream");
    const first = session.streams[0];
    await eventually(() => receiptHeartbeat(session.identityHome) !== undefined, "the stream was never confirmed live");
    t.mock.timers.tick(75_000 - 1);
    await pause(50);
    assert.equal(first.closed, false, "the stream closed before 75 seconds of silence");
    t.mock.timers.tick(1);
    await eventually(() => first.closed, "S4d: a stream silent for 75 seconds must be closed");
    await eventually(
      () => session.statuses.some((status) => status.includes("aweb events down; retrying")),
      "the silent stream was not reported disconnected",
    );
    assert.deepEqual(session.logs, ["aweb: event stream disconnected (connection timed out) — retrying in 1s"]);
    assert.equal(session.streams.length, 1, "the bundle reconnected without waiting its retry delay");
    // The first retry waits at most the policy's minimum delay of one second.
    t.mock.timers.tick(1_000);
    await eventually(() => session.streams.length === 2, "the bundle did not reconnect after the retry delay");
  } finally {
    await session.close();
  }
});

test("Pi's settled backoff sleeps leave no listener on the session signal", async (t) => {
  const session = await startPiSession(t, (request) => json(request.response, 503, { detail: "unavailable" }));
  try {
    await eventually(() => session.streams.length === 1, "the bundle never opened the event stream");
    // Each refused attempt backs off by at most 15 s; one-second steps keep
    // advancing whichever sleep is pending.
    for (let step = 0; session.streams.length < 8; step += 1) {
      assert.ok(step < 200, `the bundle stopped retrying after ${session.streams.length} attempts`);
      const seen = session.streams.length;
      t.mock.timers.tick(1_000);
      await pause(5);
      if (session.streams.length > seen) await pause(5);
    }
    const counts = session.streams.map((stream) => stream.sessionListeners);
    assert.ok(counts.every((count) => count > 0), `the session signal was not observed: ${counts}`);
    assert.equal(counts[7], counts[1], `S4e: listeners on the session signal grew across backoffs: ${counts}`);
    // A refusal that repeats is reported once.
    assert.deepEqual(session.logs, ["aweb: event stream disconnected (http 503) — retrying in 1s"]);
  } finally {
    await session.close();
  }
});
