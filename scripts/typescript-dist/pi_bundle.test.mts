// Behaviour of the built Pi extension bundle named by AWEB_PI_DIST. Run by
// scripts/test-typescript-dist-freshness.sh against the production build and
// against bundles rebuilt from a mutated source.
//
// The stream cases host the bundle's default export as Pi does, against an
// event server on 127.0.0.1 owned by the test. node:test mock timers drive the
// bundle's setTimeout and Date; the sockets stay real.
import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

// Every fixture directory lives in one scratch directory, removed when the
// process exits whether the tests passed or not.
const scratch = temporaryDirectory("aweb-pi-dist-");
process.on("exit", () => { rmSync(scratch, { recursive: true, force: true }); });
function owned(prefix: string): string {
  return mkdtempSync(join(scratch, prefix));
}

// The bundle resolves ~/.config/aw paths at module load, so the isolated home
// and environment are in place before it is imported.
process.env.HOME = owned("home-");
for (const name of ["AWEB_IDENTITY_HOME", "AWEB_DELIVERY", "AWID_REGISTRY_URL", "AWEB_URL"]) delete process.env[name];
// The fixture aw answers the one bootstrap command the extension runs.
const bin = owned("bin-");
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
    const workdir = owned("config-");
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

/** Settle work within `ms` of real time, or reject naming it. */
function within<T>(work: Promise<T> | T, ms: number, what: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = realSetTimeout(() => reject(new Error(`${what} did not settle within ${ms} ms`)), ms);
    Promise.resolve(work).then(resolve, reject).finally(() => clearTimeout(timer));
  });
}

type Extension = (pi: unknown) => void;

/**
 * Start a Pi session from `extension` (the bundle's default export) against
 * an owned event server. `answer` decides each stream request's response.
 *
 * Everything acquired is released by close(), which also runs if startup
 * fails: the session (bounded in real time), the warning capture and the
 * server, each even when an earlier step fails. close() is registered with
 * the test as well, so a failed assertion still releases it.
 */
async function startPiSession(
  t: TestContext,
  answer: StreamAnswer,
  options: { extension?: Extension; observe?: (server: { listening: boolean }) => void } = {},
) {
  const workdir = owned("session-");
  const identityHome = join(workdir, ".aw");
  await writeTestPrincipal(identityHome, { alias: "pi-dist", seedByte: 71, teamID: "dist:aweb.test" });

  const streams: StreamRequest[] = [];
  const statuses: string[] = [];
  const logs: string[] = [];
  let sessionSignal: AbortSignal | undefined;
  const handlers = new Map<string, (event: unknown, ctx: unknown) => Promise<void> | void>();
  const ctx = {
    cwd: workdir,
    hasUI: true,
    ui: {
      theme: { fg: (_kind: string, text: string) => text },
      setStatus: (_key: string, value: string) => { statuses.push(value); },
      notify: () => {},
    },
  };

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
  options.observe?.(server.server);
  // The bundle reports stream states on console.warn; they are this test's evidence.
  const consoleWarn = console.warn;
  console.warn = (...parts: unknown[]) => { logs.push(parts.join(" ")); };

  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    const failures: unknown[] = [];
    t.mock.timers.reset();
    const shutdown = handlers.get("session_shutdown");
    if (shutdown) {
      try {
        await within(shutdown({}, ctx), 5_000, "session_shutdown");
      } catch (error) {
        failures.push(error);
      }
    }
    console.warn = consoleWarn;
    try {
      await within(server.close(), 5_000, "closing the event server");
      await eventually(() => streams.every((stream) => stream.closed), "a stream socket outlived the session");
    } catch (error) {
      failures.push(error);
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length) throw new AggregateError(failures, "the Pi session was not released cleanly");
  })();
  t.after(() => close().catch(() => {}));

  try {
    const workspace = join(identityHome, "workspace.yaml");
    writeFileSync(workspace, readFileSync(workspace, "utf8").replace(/^aweb_url: .*$/m, `aweb_url: ${server.url}`));
    const pi = {
      on(event: string, handler: (event: unknown, ctx: unknown) => Promise<void> | void) { handlers.set(event, handler); },
      sendMessage() {},
    };
    t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.now() });
    (options.extension ?? bundle.default)(pi);
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
      const sessionStart = handlers.get("session_start");
      assert.ok(sessionStart, "the extension registered no session_start handler");
      await sessionStart({}, ctx);
    } finally {
      globalThis.AbortController = NativeAbortController;
    }
    assert.ok(sessionSignal, "session_start constructed no AbortController");
  } catch (error) {
    await close().catch(() => {});
    throw error;
  }

  return { streams, statuses, logs, identityHome, close };
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

/** The bundle's extension with its session hooks wrapped, to fault the harness's host. */
function bundleWith(hooks: {
  afterStart?: () => Promise<void>;
  shutdown?: (real: () => Promise<void>) => Promise<void>;
}): Extension {
  type Handler = (event: unknown, ctx: unknown) => Promise<void> | void;
  return (pi: any) => bundle.default({
    ...pi,
    on(event: string, handler: Handler) {
      if (event === "session_start" && hooks.afterStart) {
        return pi.on(event, async (e: unknown, c: unknown) => { await handler(e, c); await hooks.afterStart!(); });
      }
      if (event === "session_shutdown" && hooks.shutdown) {
        return pi.on(event, () => hooks.shutdown!(async () => { await handler({}, undefined); }));
      }
      return pi.on(event, handler);
    },
  });
}

/** Records the event server and whether the bundle has opened its stream. */
function serverWatch() {
  const watch: { server?: any; streamOpened: boolean } = { streamOpened: false };
  return {
    watch,
    observe(server: any) {
      watch.server = server;
      server.on("request", (request: IncomingMessage) => {
        if ((request.url || "").startsWith("/v1/events/stream")) watch.streamOpened = true;
      });
    },
  };
}

test("a Pi session whose start fails after opening its stream is released", async (t) => {
  const { watch, observe } = serverWatch();
  const warn = console.warn;
  const extension = bundleWith({
    afterStart: async () => {
      await eventually(() => watch.streamOpened, "the bundle never opened the event stream");
      throw new Error("start failed after the stream opened");
    },
  });
  await assert.rejects(startPiSession(t, keepOpen, { extension, observe }), /start failed after the stream opened/);
  assert.equal(watch.server.listening, false, "the event server outlived a failed start");
  assert.equal(console.warn, warn, "the warning capture outlived a failed start");
});

test("a Pi session whose shutdown fails still releases the server and warning capture", async (t) => {
  const { watch, observe } = serverWatch();
  const warn = console.warn;
  const extension = bundleWith({
    shutdown: async (real) => { await real(); throw new Error("shutdown failed"); },
  });
  const session = await startPiSession(t, keepOpen, { extension, observe });
  await eventually(() => watch.streamOpened, "the bundle never opened the event stream");
  await assert.rejects(session.close(), /shutdown failed/);
  assert.equal(watch.server.listening, false, "the event server outlived a failed shutdown");
  assert.equal(console.warn, warn, "the warning capture outlived a failed shutdown");
});

test("a Pi session whose shutdown never settles is released within its real-time bound", { timeout: 20_000 }, async (t) => {
  const { watch, observe } = serverWatch();
  const extension = bundleWith({
    shutdown: (real) => { void real(); return new Promise(() => {}); },
  });
  const session = await startPiSession(t, keepOpen, { extension, observe });
  await eventually(() => watch.streamOpened, "the bundle never opened the event stream");
  await assert.rejects(session.close(), /session_shutdown did not settle within 5000 ms/);
  assert.equal(watch.server.listening, false, "the event server outlived a hung shutdown");
});
