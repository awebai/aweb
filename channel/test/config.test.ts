import { describe, expect, test } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { resolveConfig } from "../src/config.js";

describe("resolveConfig", () => {
  test("loads channel config from .aw workspace and identity state", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(awDir, { recursive: true });

    writeFileSync(join(awDir, "workspace.yaml"), [
      "server_url: https://app.aweb.ai",
      "api_key: aw_sk_test",
      "identity_handle: support",
      "namespace_slug: acme.com",
      "project_slug: acme",
      "",
    ].join("\n"));
    writeFileSync(join(awDir, "identity.yaml"), [
      "did: did:key:z6Mktest",
      "stable_id: did:aw:test",
      "address: acme.com/support",
      "",
    ].join("\n"));

    const config = await resolveConfig(dir);
    expect(config).toEqual({
      baseURL: "https://app.aweb.ai",
      apiKey: "aw_sk_test",
      did: "did:key:z6Mktest",
      stableID: "did:aw:test",
      address: "acme.com/support",
      alias: "support",
      projectSlug: "acme",
    });
  });

  test("falls back to workspace identity fields when identity.yaml is absent", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(awDir, { recursive: true });

    writeFileSync(join(awDir, "workspace.yaml"), [
      "server_url: https://app.aweb.ai",
      "api_key: aw_sk_test",
      "identity_handle: alice",
      "namespace_slug: myteam",
      "project_slug: myteam",
      "did: did:key:z6Mkworkspace",
      "stable_id: did:aw:workspace",
      "",
    ].join("\n"));

    const config = await resolveConfig(dir);
    expect(config).toEqual({
      baseURL: "https://app.aweb.ai",
      apiKey: "aw_sk_test",
      did: "did:key:z6Mkworkspace",
      stableID: "did:aw:workspace",
      address: "myteam/alice",
      alias: "alice",
      projectSlug: "myteam",
    });
  });
});
