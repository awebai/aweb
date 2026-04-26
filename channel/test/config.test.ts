import { describe, expect, test } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { resolveConfig } from "../src/config.js";
import { computeDIDKey } from "../src/identity/did.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

function writeSigningKey(path: string, seed: Uint8Array): void {
  const pem = [
    "-----BEGIN ED25519 PRIVATE KEY-----",
    Buffer.from(seed).toString("base64"),
    "-----END ED25519 PRIVATE KEY-----",
    "",
  ].join("\n");
  writeFileSync(path, pem);
}

async function writeTeamCertificate(
  path: string,
  seed: Uint8Array,
  fields: {
    team_id: string;
    alias: string;
    member_did_aw?: string;
    member_address?: string;
  },
): Promise<{ did: string }> {
  const publicKey = ed.getPublicKey(seed);
  const did = computeDIDKey(publicKey);
  writeFileSync(path, JSON.stringify({
    version: 1,
    certificate_id: "cert-test",
    team_id: fields.team_id,
    team_did_key: "did:key:z6Mktestteam",
    member_did_key: did,
    member_did_aw: fields.member_did_aw,
    member_address: fields.member_address,
    alias: fields.alias,
    lifetime: "ephemeral",
    issued_at: "2026-04-09T00:00:00Z",
    signature: "sig",
  }, null, 2) + "\n");
  return { did };
}

function writeWorkspaceBinding(awDir: string, teamID: string, alias: string, certPath: string): void {
  writeFileSync(join(awDir, "workspace.yaml"), [
    "aweb_url: https://app.aweb.ai",
    "memberships:",
    `  - team_id: ${teamID}`,
    `    alias: ${alias}`,
    `    cert_path: ${certPath}`,
    "",
  ].join("\n"));
}

function writeTeamState(awDir: string, teamID: string, alias: string, certPath: string): void {
  writeFileSync(join(awDir, "teams.yaml"), [
    `active_team: ${teamID}`,
    "memberships:",
    `  - team_id: ${teamID}`,
    `    alias: ${alias}`,
    `    cert_path: ${certPath}`,
    "",
  ].join("\n"));
}

describe("resolveConfig", () => {
  test("loads channel config when workspace omits active_team and teams.yaml selects the team", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(7);
    const stableID = "did:aw:test";
    const address = "acme.com/support";
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "backend__acme.com.pem"), seed, {
      team_id: "backend:acme.com",
      alias: "support",
      member_did_aw: stableID,
      member_address: address,
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:acme.com", "support", "team-certs/backend__acme.com.pem");
    writeTeamState(awDir, "backend:acme.com", "support", "team-certs/backend__acme.com.pem");
    writeFileSync(join(awDir, "identity.yaml"), [
      `did: ${did}`,
      `stable_id: ${stableID}`,
      `address: ${address}`,
      "registry_url: https://registry.example.test",
      "",
    ].join("\n"));

    const config = await resolveConfig(dir);
    expect(config.baseURL).toBe("https://app.aweb.ai");
    expect(config.teamID).toBe("backend:acme.com");
    expect(config.alias).toBe("support");
    expect(config.did).toBe(did);
    expect(config.stableID).toBe(stableID);
    expect(config.address).toBe(address);
    expect(config.registryURL).toBe("https://registry.example.test");
    expect(config.signingKey).toEqual(seed);
    expect(config.teamCertificateHeader).toBeTruthy();
  });

  test("ignores stray active_team in workspace.yaml and uses teams.yaml as source of truth", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(19);
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "ops__acme.com.pem"), seed, {
      team_id: "ops:acme.com",
      alias: "ops-alice",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeFileSync(join(awDir, "workspace.yaml"), [
      "aweb_url: https://app.aweb.ai",
      "active_team: backend:acme.com",
      "memberships:",
      "  - team_id: backend:acme.com",
      "    alias: backend-alice",
      "    cert_path: team-certs/backend__acme.com.pem",
      "  - team_id: ops:acme.com",
      "    alias: ops-alice",
      "    cert_path: team-certs/ops__acme.com.pem",
      "",
    ].join("\n"));
    writeTeamState(awDir, "ops:acme.com", "ops-alice", "team-certs/ops__acme.com.pem");

    const config = await resolveConfig(dir);
    expect(config.teamID).toBe("ops:acme.com");
    expect(config.alias).toBe("ops-alice");
    expect(config.did).toBe(did);
  });

  test("prefers active team certificate member_address over identity address", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(13);
    const stableID = "did:aw:amy";
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "backend__aweb.ai.pem"), seed, {
      team_id: "backend:aweb.ai",
      alias: "amy",
      member_did_aw: stableID,
      member_address: "aweb.ai/amy",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:aweb.ai", "amy", "team-certs/backend__aweb.ai.pem");
    writeTeamState(awDir, "backend:aweb.ai", "amy", "team-certs/backend__aweb.ai.pem");
    writeFileSync(join(awDir, "identity.yaml"), [
      `did: ${did}`,
      `stable_id: ${stableID}`,
      "address: juan.aweb.ai/amy",
      "",
    ].join("\n"));

    const config = await resolveConfig(dir);
    expect(config.address).toBe("aweb.ai/amy");
  });

  test("derives identity from team certificate when identity.yaml is absent", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(9);
    const { did } = await writeTeamCertificate(join(awDir, "team-certs", "backend__acme.com.pem"), seed, {
      team_id: "backend:acme.com",
      alias: "alice",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");
    writeTeamState(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");

    const config = await resolveConfig(dir);
    expect(config.baseURL).toBe("https://app.aweb.ai");
    expect(config.teamID).toBe("backend:acme.com");
    expect(config.alias).toBe("alice");
    expect(config.did).toBe(did);
    expect(config.stableID).toBe("");
    expect(config.address).toBe("");
    expect(config.registryURL).toBe("");
  });

  test("errors clearly when the team-certs directory is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(awDir, { recursive: true });
    const seed = new Uint8Array(32).fill(11);
    writeSigningKey(join(awDir, "signing.key"), seed);

    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");
    writeTeamState(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");

    await expect(resolveConfig(dir)).rejects.toThrow(/migrate-multi-team/);
  });

  test("errors clearly when teams.yaml is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(17);
    await writeTeamCertificate(join(awDir, "team-certs", "backend__acme.com.pem"), seed, {
      team_id: "backend:acme.com",
      alias: "alice",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);
    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", "team-certs/backend__acme.com.pem");

    await expect(resolveConfig(dir)).rejects.toThrow(/teams\.yaml/);
  });

  test("errors clearly on the legacy single-team workspace shape", async () => {
    const dir = mkdtempSync(join(tmpdir(), "channel-config-"));
    const awDir = join(dir, ".aw");
    mkdirSync(awDir, { recursive: true });

    writeFileSync(join(awDir, "workspace.yaml"), [
      "aweb_url: http://localhost:8000",
      "team_address: acme.com/backend",
      "alias: alice",
      "",
    ].join("\n"));

    await expect(resolveConfig(dir)).rejects.toThrow(/migrate-multi-team/);
  });
});
