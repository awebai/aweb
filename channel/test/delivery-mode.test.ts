import { createServer, type IncomingMessage } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "vitest";
import { createShadowedPrincipalFixture } from "../../channel-core/test/helpers/config_fixture.js";
import { launchPackagedMCPChild } from "./helpers/packaged_mcp.js";
import { CHANNEL_EXTERNAL_DELIVERY_NOTICE, resolveChannelDelivery } from "../src/index.js";

const channelRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const originalHome = process.env.HOME;
const originalDelivery = process.env.AWEB_DELIVERY;

interface ProbeServer {
  close(): Promise<void>;
  requests: string[];
  url: string;
}

let child: ChildProcessWithoutNullStreams | undefined;
let probe: ProbeServer | undefined;

afterEach(async () => {
  child?.kill("SIGTERM");
  child = undefined;
  await probe?.close();
  probe = undefined;
  restoreEnvironment("HOME", originalHome);
  restoreEnvironment("AWEB_DELIVERY", originalDelivery);
});

describe("resolveChannelDelivery", () => {
  test("an unset AWEB_DELIVERY registers the native channel", () => {
    expect(resolveChannelDelivery({})).toEqual({ mode: "channel" });
    expect(resolveChannelDelivery({ AWEB_DELIVERY: "channel" })).toEqual({ mode: "channel" });
  });

  test("session reports external delivery in one line", () => {
    const decision = resolveChannelDelivery({ AWEB_DELIVERY: "session" });
    expect(decision.mode).toBe("session");
    expect(decision.notice).toBe(CHANNEL_EXTERNAL_DELIVERY_NOTICE);
    expect(decision.notice?.split("\n")).toHaveLength(1);
  });

  test("an unknown value warns and registers the native channel", () => {
    const decision = resolveChannelDelivery({ AWEB_DELIVERY: "external" });
    expect(decision.mode).toBe("channel");
    expect(decision.warning).toContain("AWEB_DELIVERY");
    expect(decision.notice).toBeUndefined();
  });
});

describe("packaged Claude channel delivery mode", () => {
  test("AWEB_DELIVERY=session opens no event stream and registers no channel", async () => {
    const launched = await launchFixtureChild("session");

    expect(launched.initialize.serverInfo?.name).toBe("aweb-channel");
    expect(launched.initialize.capabilities?.experimental?.["claude/channel"]).toBeUndefined();
    expect(launched.stderr()).toContain(CHANNEL_EXTERNAL_DELIVERY_NOTICE);

    // The whole point of the opt-out: the external wake path owns the one
    // per-identity stream, so this process must never open it.
    await settle(1_500);
    expect(probe?.requests).toEqual([]);
  }, 20_000);

  test("an unset AWEB_DELIVERY opens the event stream exactly as before", async () => {
    const launched = await launchFixtureChild(undefined);

    expect(launched.initialize.capabilities?.experimental?.["claude/channel"]).toEqual({});
    expect(launched.stderr()).not.toContain("AWEB_DELIVERY");
    await expectStreamOpened(launched.stderr);
  }, 20_000);

  test("an unknown AWEB_DELIVERY warns once and still opens the event stream", async () => {
    const launched = await launchFixtureChild("external");

    expect(launched.initialize.capabilities?.experimental?.["claude/channel"]).toEqual({});
    const warnings = launched.stderr().split("\n").filter((line) => line.includes("AWEB_DELIVERY"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("external");
    await expectStreamOpened(launched.stderr);
  }, 20_000);
});

async function launchFixtureChild(delivery: string | undefined) {
  const { workdir } = await createShadowedPrincipalFixture();
  probe = await startProbeServer();
  setAwebURL(join(workdir, ".aw"), probe.url);

  process.env.HOME = mkdtempSync(join(tmpdir(), "claude-channel-delivery-home-"));
  restoreEnvironment("AWEB_DELIVERY", delivery);

  const launched = await launchPackagedMCPChild(channelRoot, workdir);
  child = launched.child;
  return launched;
}

async function expectStreamOpened(stderr: () => string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    if (probe && probe.requests.length > 0) break;
    await settle(50);
  }
  expect(probe?.requests[0], `channel did not open the event stream\n${stderr()}`)
    .toMatch(/^\/v1\/events\/stream\?deadline=/);
}

async function startProbeServer(): Promise<ProbeServer> {
  const requests: string[] = [];
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
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("probe server did not bind a TCP port");

  return {
    requests,
    url: `http://127.0.0.1:${address.port}`,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  };
}

function setAwebURL(identityHome: string, url: string): void {
  const path = join(identityHome, "workspace.yaml");
  const workspace = readFileSync(path, "utf8");
  writeFileSync(path, workspace.replace(/^aweb_url: .*$/m, `aweb_url: ${url}`));
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function settle(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms); });
}
