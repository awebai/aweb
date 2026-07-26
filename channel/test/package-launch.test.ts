import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "vitest";
import { launchPackagedMCPChild } from "./helpers/packaged_mcp.js";

const channelRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const originalHome = process.env.HOME;
const originalIdentityHome = process.env.AWEB_IDENTITY_HOME;
let child: ChildProcessWithoutNullStreams | undefined;

afterEach(() => {
  child?.kill("SIGTERM");
  child = undefined;
  restoreEnvironment("HOME", originalHome);
  restoreEnvironment("AWEB_IDENTITY_HOME", originalIdentityHome);
});

test("freshly built ESM bundle completes MCP initialization through the packaged command", async () => {
  const workdir = createInitializedWorkdir();
  process.env.HOME = mkdtempSync(join(tmpdir(), "claude-channel-launch-home-"));
  delete process.env.AWEB_IDENTITY_HOME;

  const launched = await launchPackagedMCPChild(channelRoot, workdir);
  child = launched.child;

  expect(launched.args).toEqual([join(channelRoot, "dist", "index.js")]);
});

function createInitializedWorkdir(): string {
  const workdir = mkdtempSync(join(tmpdir(), "claude-channel-launch-workdir-"));
  const identityHome = join(workdir, ".aw");
  const certPath = "team-certs/package-test.pem";
  const vectors = JSON.parse(readFileSync(join(channelRoot, "test", "vectors.json"), "utf8")) as {
    did: string;
    seed: string;
    stableID: string;
  };
  mkdirSync(join(identityHome, "team-certs"), { recursive: true });
  writeFileSync(join(identityHome, "signing.key"), [
    "-----BEGIN ED25519 PRIVATE KEY-----",
    vectors.seed,
    "-----END ED25519 PRIVATE KEY-----",
    "",
  ].join("\n"));
  writeFileSync(join(identityHome, certPath), `${JSON.stringify({
    version: 1,
    certificate_id: "cert-package-test",
    team_id: "package-test:aweb.test",
    team_did_key: "did:key:z6Mktestteam",
    member_did_key: vectors.did,
    member_did_aw: vectors.stableID,
    member_address: "aweb.test/package-test",
    alias: "package-test",
    lifetime: "ephemeral",
    issued_at: "2026-07-26T00:00:00Z",
    signature: "sig",
  }, null, 2)}\n`);
  writeFileSync(join(identityHome, "workspace.yaml"), [
    "aweb_url: http://127.0.0.1:1",
    "memberships:",
    "  - team_id: package-test:aweb.test",
    "    alias: package-test",
    `    cert_path: ${certPath}`,
    "",
  ].join("\n"));
  writeFileSync(join(identityHome, "teams.yaml"), [
    "active_team: package-test:aweb.test",
    "memberships:",
    "  - team_id: package-test:aweb.test",
    "    alias: package-test",
    `    cert_path: ${certPath}`,
    "",
  ].join("\n"));
  return workdir;
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
