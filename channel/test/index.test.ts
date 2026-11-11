import { afterEach, describe, expect, test } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { CHANNEL_INSTRUCTIONS, createChannelRegistryResolver, loadChannelConfig, isDirectExecution, resolveRegistryFallbackURL, handleClaudeStreamState, notifyClaudeAwakening } from "../src/index.js";
import { eventStreamRefusedAwakening } from "@awebai/channel-core";
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

describe("the refused notice", () => {
  test("the start of a refusal episode is the one stream state presented to Claude, as a notice from the channel itself", async () => {
    const logs: string[] = [];
    const notifications: any[] = [];
    const mcp = { notification: async (item: unknown) => { notifications.push(item); } } as any;
    const nextAttemptAt = new Date(2026, 2, 1, 9, 5).getTime();
    const refused = { state: "refused" as const, cause: "401", retryInMs: 60_000, nextAttemptAt, startsEpisode: true as const };

    // The stream state handler is the operator surface: it logs and presents nothing.
    handleClaudeStreamState(refused, (message) => logs.push(message));
    handleClaudeStreamState({ state: "reconnected", endedRefusal: "401" }, (message) => logs.push(message));
    expect(logs).toHaveLength(2);
    expect(notifications).toHaveLength(0);

    // The channel loop presents the notice through the plugin's awakening path.
    await notifyClaudeAwakening(mcp, eventStreamRefusedAwakening(refused));
    expect(notifications).toEqual([{
      method: "notifications/claude/channel",
      params: {
        content: "The aweb server refused this channel's event stream (401). Mail and chat will not arrive until the stream is accepted again. The next attempt is at 09:05.",
        meta: {
          type: "channel",
          notice: "event_stream_refused",
          cause: "401",
          next_attempt_at: new Date(nextAttemptAt).toISOString(),
        },
      },
    }]);
  });

  test("the plugin tells Claude what a channel notice is", () => {
    expect(CHANNEL_INSTRUCTIONS).toContain(
      'Channel notices (type="channel") come from this plugin itself, not from another agent',
    );
  });
});

describe("refused stream handling", () => {
  test("the stream state handler logs a refused stream once on entry and once on exit", () => {
    const logs: string[] = [];
    const nextAttemptAt = new Date(2026, 2, 1, 9, 5).getTime();

    handleClaudeStreamState({ state: "refused", cause: "401", retryInMs: 60_000, nextAttemptAt }, (message) => logs.push(message));
    handleClaudeStreamState({ state: "reconnected", endedRefusal: "401" }, (message) => logs.push(message));

    expect(logs).toEqual([
      "aweb: event stream refused: 401, next try 09:05",
      "aweb: event stream accepted again (was refused: 401)",
    ]);
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
