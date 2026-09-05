import assert from "node:assert/strict";
import test from "node:test";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

import { createShadowedPrincipalFixture } from "../../channel-core/test/helpers/config_fixture.ts";

// The extension and channel-core resolve ~/.config/aw paths at module load, so
// a fake HOME must be in place before the module under test is imported.
const testHome = mkdtempSync(join(tmpdir(), "aweb-pi-delivery-home-"));
process.env.HOME = testHome;
delete process.env.AWEB_IDENTITY_HOME;

const {
  default: awebPiExtension,
  PI_EXTERNAL_DELIVERY_NOTICE,
  PI_EXTERNAL_DELIVERY_STATUS,
  resolvePiDelivery,
} = await import("../src/index.ts");

test("an unset AWEB_DELIVERY leaves delivery with the Pi channel loop", () => {
  assert.deepEqual(resolvePiDelivery({}), { mode: "channel" });
  assert.deepEqual(resolvePiDelivery({ AWEB_DELIVERY: "channel" }), { mode: "channel" });
});

test("AWEB_DELIVERY=session reports external delivery in one line and one status", () => {
  const decision = resolvePiDelivery({ AWEB_DELIVERY: "session" });
  assert.equal(decision.mode, "session");
  assert.equal(decision.notice, PI_EXTERNAL_DELIVERY_NOTICE);
  assert.equal(decision.notice?.split("\n").length, 1);
  assert.equal(decision.status, PI_EXTERNAL_DELIVERY_STATUS);
});

test("an unknown AWEB_DELIVERY warns and keeps the Pi channel loop", () => {
  const decision = resolvePiDelivery({ AWEB_DELIVERY: "external" });
  assert.equal(decision.mode, "channel");
  assert.match(String(decision.warning), /AWEB_DELIVERY/);
  assert.equal(decision.notice, undefined);
});

test("AWEB_DELIVERY=session starts a Pi session that opens no event stream", async () => {
  const harness = await startSession("session");
  try {
    // The external wake path owns the one per-identity stream; this extension
    // must not open a second consumer of it.
    await settle(1_000);
    assert.deepEqual(harness.requests, []);
    assert.ok(
      harness.messages.some((message) => message.content === PI_EXTERNAL_DELIVERY_NOTICE),
      `expected the external-delivery notice, got ${JSON.stringify(harness.messages)}`,
    );
    assert.equal(
      harness.messages.filter((message) => message.content === PI_EXTERNAL_DELIVERY_NOTICE).length,
      1,
    );
    assert.ok(
      harness.statuses.some(([, value]) => value.includes(PI_EXTERNAL_DELIVERY_STATUS)),
      `expected the external-delivery status line, got ${JSON.stringify(harness.statuses)}`,
    );
    // Identity, skills, welcome and the aw CLI path are unaffected.
    assert.ok(harness.messages.some((message) => message.customType === "aweb-welcome"));
  } finally {
    await harness.close();
  }
});

test("an unset AWEB_DELIVERY starts a Pi session that opens the event stream", async () => {
  const harness = await startSession(undefined);
  try {
    await harness.waitForRequest();
    assert.match(harness.requests[0] || "", /^\/v1\/events\/stream\?deadline=/);
    assert.ok(harness.messages.every((message) => message.content !== PI_EXTERNAL_DELIVERY_NOTICE));
  } finally {
    await harness.close();
  }
});

test("an unknown AWEB_DELIVERY warns once and still opens the event stream", async () => {
  const harness = await startSession("external");
  try {
    await harness.waitForRequest();
    assert.match(harness.requests[0] || "", /^\/v1\/events\/stream\?deadline=/);
    const warnings = harness.messages.filter((message) => String(message.content).includes("AWEB_DELIVERY"));
    assert.equal(warnings.length, 1);
    assert.match(String(warnings[0].content), /external/);
  } finally {
    await harness.close();
  }
});

interface RecordedMessage {
  customType?: string;
  content?: string;
  details?: Record<string, unknown>;
}

interface SessionHarness {
  close(): Promise<void>;
  messages: RecordedMessage[];
  requests: string[];
  statuses: Array<[string, string]>;
  waitForRequest(): Promise<void>;
}

async function startSession(delivery: string | undefined): Promise<SessionHarness> {
  const { workdir } = await createShadowedPrincipalFixture();
  const requests: string[] = [];
  const server = await startProbeServer(requests);
  setAwebURL(join(workdir, ".aw"), serverURL(server));

  // A stub `aw` first on PATH keeps the readiness probe hermetic: the extension
  // only needs `aw workspace status` to succeed.
  const binDir = mkdtempSync(join(tmpdir(), "aweb-pi-delivery-bin-"));
  const awPath = join(binDir, "aw");
  writeFileSync(awPath, "#!/bin/sh\nexit 0\n");
  chmodSync(awPath, 0o755);
  const originalPath = process.env.PATH;
  process.env.PATH = `${binDir}${delimiter}${originalPath || ""}`;
  const originalDelivery = process.env.AWEB_DELIVERY;
  if (delivery === undefined) {
    delete process.env.AWEB_DELIVERY;
  } else {
    process.env.AWEB_DELIVERY = delivery;
  }
  // The welcome sentinel is keyed by workspace directory, and every case gets a
  // fresh fixture, so no case is gated by an earlier one.
  const messages: RecordedMessage[] = [];
  const statuses: Array<[string, string]> = [];
  const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
  const pi = {
    on(event: string, handler: (event: unknown, ctx: unknown) => unknown) { handlers.set(event, handler); },
    sendMessage(message: RecordedMessage) { messages.push(message); },
  };
  const ctx = {
    cwd: workdir,
    hasUI: true,
    ui: {
      theme: { fg: (_role: string, text: string) => text },
      setStatus: (key: string, value: string) => { statuses.push([key, value]); },
      notify: () => {},
    },
  };

  awebPiExtension(pi as any);
  const sessionStart = handlers.get("session_start");
  assert.ok(sessionStart, "extension did not register a session_start handler");
  await sessionStart({}, ctx);

  return {
    messages,
    requests,
    statuses,
    waitForRequest: async () => {
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline && requests.length === 0) await settle(25);
      assert.ok(requests.length > 0, "the Pi extension never opened the event stream");
    },
    close: async () => {
      const shutdown = handlers.get("session_shutdown");
      if (shutdown) await shutdown({}, ctx);
      if (originalDelivery === undefined) {
        delete process.env.AWEB_DELIVERY;
      } else {
        process.env.AWEB_DELIVERY = originalDelivery;
      }
      process.env.PATH = originalPath;
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  };
}

async function startProbeServer(requests: string[]): Promise<Server> {
  const server = createServer((request: IncomingMessage, response) => {
    requests.push(request.url || "");
    response.writeHead(200, {
      "cache-control": "no-cache",
      connection: "keep-alive",
      "content-type": "text/event-stream",
    });
    response.write(": connected\n\n");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server;
}

function serverURL(server: Server): string {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("probe server did not bind a TCP port");
  return `http://127.0.0.1:${address.port}`;
}

function setAwebURL(identityHome: string, url: string): void {
  const path = join(identityHome, "workspace.yaml");
  const workspace = readFileSync(path, "utf8");
  writeFileSync(path, workspace.replace(/^aweb_url: .*$/m, `aweb_url: ${url}`));
}

function settle(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms); });
}
