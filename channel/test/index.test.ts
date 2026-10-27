import { afterEach, describe, expect, test } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { createChannelRegistryResolver, loadChannelConfig, isDirectExecution, resolveRegistryFallbackURL, handleClaudeStreamState, notifyClaudeAwakening } from "../src/index.js";
import { createShadowedPrincipalFixture } from "../../channel-core/test/helpers/config_fixture.js";

describe("loadChannelConfig", () => {
  const originalIdentityHome = process.env.AWEB_IDENTITY_HOME;

  afterEach(() => {
    if (originalIdentityHome === undefined) {
      delete process.env.AWEB_IDENTITY_HOME;
    } else {
      process.env.AWEB_IDENTITY_HOME = originalIdentityHome;
    }
  });

  test("Claude loads the external principal instead of a valid working-directory shadow", async () => {
    const { external, shadow, workdir } = await createShadowedPrincipalFixture();
    process.env.AWEB_IDENTITY_HOME = external.identityHome;

    const config = await loadChannelConfig(workdir);

    expect(config.alias).toBe(external.alias);
    expect(config.did).toBe(external.did);
    expect(config.signingKey).toEqual(external.seed);
    expect(config.did).not.toBe(shadow.did);
  });
});

describe("createChannelRegistryResolver", () => {
  test("discovers a foreign authority from the concrete Channel identity address", async () => {
    const calls: string[] = [];
    const registry = createChannelRegistryResolver({
      registryURL: "https://home.registry.example",
      address: "home.example/alice",
    }, async (hostname) => {
      calls.push(hostname);
      return [["awid=v1; controller=did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd; registry=https://foreign.registry.example;"]];
    });

    await expect(registry.discoverRegistry("foreign.example"))
      .resolves.toBe("https://foreign.registry.example");
    expect(calls).toEqual(["_awid.foreign.example"]);
  });
});

describe("stream state handling", () => {
  test("transport reconnect and disconnect are diagnostics, not Claude model input", async () => {
    const logs: string[] = [];
    const notifications: unknown[] = [];
    const mcp = { notification: async (item: unknown) => { notifications.push(item); } } as any;

    handleClaudeStreamState({ state: "disconnected", cause: "network unavailable", retryInMs: 1000 }, (message) => logs.push(message));
    handleClaudeStreamState({ state: "reconnected" }, (message) => logs.push(message));
    handleClaudeStreamState({ state: "disconnected", cause: "connection closed", retryInMs: 2000 }, (message) => logs.push(message));

    expect(logs).toHaveLength(3);
    expect(notifications).toHaveLength(0);

    await notifyClaudeAwakening(mcp, { kind: "mail", content: "hello", deliveryIntent: "wake", meta: { type: "mail", message_id: "m1" } });
    expect(notifications).toHaveLength(1);
  });
});

describe("isDirectExecution", () => {
  const originalArgv1 = process.argv[1];
  let tempDir: string | null = null;

  afterEach(() => {
    process.argv[1] = originalArgv1;
    if (tempDir) {
      rmSync(tempDir, { recursive: true, force: true });
      tempDir = null;
    }
  });

  test("treats the npm bin symlink as direct execution", () => {
    tempDir = mkdtempSync(join(tmpdir(), "channel-bin-"));

    const target = join(tempDir, "node_modules", "@awebai", "channel", "dist", "index.js");
    mkdirSync(join(tempDir, "node_modules", ".bin"), { recursive: true });
    mkdirSync(join(tempDir, "node_modules", "@awebai", "channel", "dist"), { recursive: true });
    writeFileSync(target, "#!/usr/bin/env node\n");

    const binPath = join(tempDir, "node_modules", ".bin", "channel");
    symlinkSync(target, binPath);

    process.argv[1] = binPath;

    expect(isDirectExecution(pathToFileURL(target).href)).toBe(true);
  });
});

describe("resolveRegistryFallbackURL", () => {
  const originalRegistryURL = process.env.AWID_REGISTRY_URL;

  afterEach(() => {
    if (originalRegistryURL === undefined) {
      delete process.env.AWID_REGISTRY_URL;
    } else {
      process.env.AWID_REGISTRY_URL = originalRegistryURL;
    }
  });

  test("uses AWID_REGISTRY_URL as a URL override", () => {
    process.env.AWID_REGISTRY_URL = "https://registry.example.test";

    expect(resolveRegistryFallbackURL("https://identity-registry.example.test"))
      .toBe("https://registry.example.test");
  });

  test("rejects AWID_REGISTRY_URL=local", () => {
    process.env.AWID_REGISTRY_URL = "local";

    expect(() => resolveRegistryFallbackURL("https://identity-registry.example.test"))
      .toThrow("AWID_REGISTRY_URL=local is not supported; set AWID_REGISTRY_URL=https://api.awid.ai");
  });

  test("falls back to identity registry_url when AWID_REGISTRY_URL is unset", () => {
    delete process.env.AWID_REGISTRY_URL;

    expect(resolveRegistryFallbackURL("https://identity-registry.example.test"))
      .toBe("https://identity-registry.example.test");
  });

  test("leaves registry fallback unset when no source is configured", () => {
    delete process.env.AWID_REGISTRY_URL;

    expect(resolveRegistryFallbackURL("")).toBeUndefined();
  });
});


test("message ingress survives the public Claude notification transport", async () => {
  const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
  const server = new Server({ name: "ingress-server", version: "1" }, { capabilities: {} });
  const client = new Client({ name: "ingress-client", version: "1" });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  let accept!: (value: unknown) => void;
  const received = new Promise<unknown>(resolve => { accept = resolve; });
  client.fallbackNotificationHandler = async notification => { accept(notification); };
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const ingress = JSON.stringify({ platform: "future_platform", presence_kind: "native",
    input_origin: "external_human", confidentiality: "hosted_readable" });
  const meta = { type: "chat", message_id: "m-ingress", ingress, verified: "false", trust_status: "failed" };
  try {
    await notifyClaudeAwakening(server, { kind: "chat", content: "hello", deliveryIntent: "wake", meta });
    expect(await received).toMatchObject({ method: "notifications/claude/channel", params: { content: "hello", meta } });
  } finally {
    await client.close();
    await server.close();
  }
});
