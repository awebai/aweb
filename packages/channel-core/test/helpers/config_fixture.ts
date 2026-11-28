import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { computeDIDKey } from "../../src/identity/did.js";

ed.etc.sha512Sync = (...messages) => sha512(ed.etc.concatBytes(...messages));

export interface TestPrincipal {
  alias: string;
  did: string;
  identityHome: string;
  seed: Uint8Array;
  teamID: string;
}

interface PrincipalOptions {
  alias: string;
  seedByte: number;
  teamID: string;
}

export function writeSigningKey(path: string, seed: Uint8Array): void {
  writeFileSync(path, [
    "-----BEGIN ED25519 PRIVATE KEY-----",
    Buffer.from(seed).toString("base64"),
    "-----END ED25519 PRIVATE KEY-----",
    "",
  ].join("\n"));
}

export async function writeTeamCertificate(
  path: string,
  seed: Uint8Array,
  fields: {
    team_id: string;
    alias: string;
    member_did_aw?: string;
    member_address?: string;
  },
): Promise<{ did: string }> {
  const did = computeDIDKey(ed.getPublicKey(seed));
  writeFileSync(path, `${JSON.stringify({
    version: 1,
    certificate_id: `cert-${fields.alias}`,
    team_id: fields.team_id,
    team_did_key: "did:key:z6Mktestteam",
    member_did_key: did,
    member_did_aw: fields.member_did_aw,
    member_address: fields.member_address,
    alias: fields.alias,
    lifetime: "ephemeral",
    issued_at: "2026-07-26T00:00:00Z",
    signature: "sig",
  }, null, 2)}\n`);
  return { did };
}

export function writeWorkspaceBinding(identityHome: string, teamID: string, alias: string, certPath: string): void {
  writeFileSync(join(identityHome, "workspace.yaml"), [
    "aweb_url: https://app.aweb.ai",
    "memberships:",
    `  - team_id: ${teamID}`,
    `    alias: ${alias}`,
    `    cert_path: ${certPath}`,
    "",
  ].join("\n"));
}

export function writeTeamState(identityHome: string, teamID: string, alias: string, certPath: string): void {
  writeFileSync(join(identityHome, "teams.yaml"), [
    `active_team: ${teamID}`,
    "memberships:",
    `  - team_id: ${teamID}`,
    `    alias: ${alias}`,
    `    cert_path: ${certPath}`,
    "",
  ].join("\n"));
}

export async function writeTestPrincipal(identityHome: string, options: PrincipalOptions): Promise<TestPrincipal> {
  const seed = new Uint8Array(32).fill(options.seedByte);
  const certPath = `team-certs/${options.teamID.replace(/[:.]/g, "_")}.pem`;

  mkdirSync(join(identityHome, "team-certs"), { recursive: true });
  writeSigningKey(join(identityHome, "signing.key"), seed);
  const { did } = await writeTeamCertificate(join(identityHome, certPath), seed, {
    team_id: options.teamID,
    alias: options.alias,
    member_did_aw: `did:aw:${options.alias}`,
    member_address: `aweb.test/${options.alias}`,
  });
  writeWorkspaceBinding(identityHome, options.teamID, options.alias, certPath);
  writeTeamState(identityHome, options.teamID, options.alias, certPath);
  writeFileSync(join(identityHome, "identity.yaml"), [
    `did: ${did}`,
    `stable_id: did:aw:${options.alias}`,
    `address: aweb.test/${options.alias}`,
    "registry_url: https://registry.example.test",
    "",
  ].join("\n"));

  return { alias: options.alias, did, identityHome, seed, teamID: options.teamID };
}

export async function createShadowedPrincipalFixture(): Promise<{
  external: TestPrincipal;
  shadow: TestPrincipal;
  workdir: string;
}> {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "channel-identity-home-")));
  const workdir = join(root, "instance");
  mkdirSync(workdir);

  const shadow = await writeTestPrincipal(join(workdir, ".aw"), {
    alias: "shadow-agent",
    seedByte: 41,
    teamID: "shadow:aweb.test",
  });
  const external = await writeTestPrincipal(join(root, "principal-home"), {
    alias: "attached-agent",
    seedByte: 42,
    teamID: "runtime:aweb.test",
  });

  return { external, shadow, workdir };
}
