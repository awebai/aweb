// Hosts the built Pi extension bundle named by AWEB_PI_DIST for the behaviour
// tests in this directory, against an event server on 127.0.0.1 owned by the
// test. node:test mock timers drive the bundle's setTimeout and Date; the
// sockets stay real.
import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { delimiter, join } from "node:path";
import type { TestContext } from "node:test";
import { pathToFileURL } from "node:url";

import {
  json,
  startLoopbackServer,
  temporaryDirectory,
  writeTestPrincipal,
} from "../../packages/channel-core/test/helpers/dist_fixture.ts";

const distPath = process.env.AWEB_PI_DIST;
if (!distPath) throw new Error("AWEB_PI_DIST must name the built Pi extension bundle");

// Every fixture directory lives in one scratch directory, removed when the
// process exits whether the tests passed or not.
const scratch = temporaryDirectory("aweb-pi-dist-");
process.on("exit", () => { rmSync(scratch, { recursive: true, force: true }); });
export function owned(prefix: string): string {
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

export const bundle = await import(pathToFileURL(distPath).href);
const realSetTimeout = globalThis.setTimeout;

export function pause(ms: number): Promise<void> {
  return new Promise((resolve) => { realSetTimeout(resolve, ms); });
}

/** Wait in real time for a condition the bundle brings about over its sockets. */
export async function eventually(condition: () => boolean, message: string, ms = 3_000): Promise<void> {
  // performance.now is real time; Date is the fake clock while timers are mocked.
  const until = performance.now() + ms;
  while (!condition()) {
    if (performance.now() > until) assert.fail(message);
    await pause(5);
  }
}

export interface StreamRequest {
  deadline: number;
  response: ServerResponse;
  closed: boolean;
  /** Listeners on the session AbortSignal when the request arrived. */
  sessionListeners: number;
}

export type StreamAnswer = (request: StreamRequest, incoming: IncomingMessage) => void;

export type Extension = (pi: unknown) => void;

/**
 * Start a Pi session from `extension` (the bundle's default export) against
 * an owned event server. `answer` decides each stream request's response.
 *
 * Everything acquired is released by close(), which also runs if startup
 * fails: the session, the warning capture and the server, each even when an
 * earlier step fails. close() is registered with the test as well, so a
 * failed assertion still releases it. A hook that never settles is not this
 * harness's to stop: the freshness runner bounds the whole test process.
 */
export async function startPiSession(
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
        await shutdown({}, ctx);
      } catch (error) {
        failures.push(error);
      }
    }
    console.warn = consoleWarn;
    try {
      await server.close();
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
export function receiptHeartbeat(identityHome: string): number | undefined {
  try {
    return Date.parse(JSON.parse(readFileSync(join(identityHome, "receive", "stream.json"), "utf8")).heartbeat_at);
  } catch {
    return undefined;
  }
}

/** Write a heartbeat comment and wait until the bundle has read it at the current fake time. */
export async function beat(session: { identityHome: string }, stream: StreamRequest): Promise<void> {
  stream.response.write(": heartbeat\n\n");
  const now = Date.now();
  await eventually(() => receiptHeartbeat(session.identityHome) === now, "the bundle did not read a heartbeat");
}

export function keepOpen(request: StreamRequest): void {
  request.response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  request.response.write(": connected\n\n");
}

/** The bundle's extension with its session hooks wrapped, to fault the harness's host. */
export function bundleWith(hooks: {
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
export function serverWatch() {
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
