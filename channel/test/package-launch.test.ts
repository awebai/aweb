import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "vitest";
import { launchPackagedMCPChild } from "./helpers/packaged_mcp.js";

const channelRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const repoRoot = dirname(channelRoot);
const channelMCPName = "aweb-channel";
const retiredQualifiedMCPName = /plugin:aweb-channel:aweb(?![A-Za-z0-9_-])/;
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
  expect(launched.declarationName).toBe(channelMCPName);
  expect(launched.runtimeName).toBe(channelMCPName);

  const plugin = JSON.parse(readFileSync(join(channelRoot, ".claude-plugin", "plugin.json"), "utf8")) as {
    name: string;
  };
  expect(`plugin:${plugin.name}:${launched.declarationName}`)
    .toBe("plugin:aweb-channel:aweb-channel");
});

test("supported source consumers do not depend on the retired qualified MCP name", () => {
  const consumerRoots = [
    join(repoRoot, "channel", "src"),
    join(repoRoot, "channel-core", "src"),
    join(repoRoot, "pi-extension", "src"),
    join(repoRoot, "cli", "go", "cmd", "aw"),
    join(repoRoot, "scripts", "lib"),
  ];
  const matches = sourceFiles(consumerRoots).filter((path) =>
    retiredQualifiedMCPName.test(readFileSync(path, "utf8"))
  );

  expect(matches).toEqual([]);
});

function sourceFiles(roots: string[]): string[] {
  const files: string[] = [];
  const visit = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) {
        visit(child);
      } else if (/\.(?:go|js|mjs|sh|ts)$/.test(entry.name)) {
        files.push(child);
      }
    }
  };
  roots.forEach(visit);
  return files;
}

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
