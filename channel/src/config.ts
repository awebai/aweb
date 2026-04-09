import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import yaml from "js-yaml";
import { loadTeamCertificate, encodeTeamCertificateHeader, type TeamCertificate } from "./identity/certificate.js";
import { computeDIDKey } from "./identity/did.js";
import { loadSigningKey } from "./identity/keys.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface AgentConfig {
  baseURL: string;
  did: string;
  stableID: string;
  address: string;
  alias: string;
  teamID: string;
  signingKey: Uint8Array;
  teamCertificateHeader: string;
}

interface WorkspaceMembership {
  team_id?: string;
  alias?: string;
  role_name?: string;
  workspace_id?: string;
  cert_path?: string;
  joined_at?: string;
}

interface WorkspaceConfig {
  aweb_url?: string;
  active_team?: string;
  memberships?: WorkspaceMembership[];
}

interface IdentityConfig {
  did?: string;
  stable_id?: string;
  address?: string;
  registry_url?: string;
}

export async function resolveConfig(workdir: string): Promise<AgentConfig> {
  const workspacePath = join(workdir, ".aw", "workspace.yaml");
  const identityPath = join(workdir, ".aw", "identity.yaml");
  const signingKeyPath = join(workdir, ".aw", "signing.key");

  const workspace = await readYAML<WorkspaceConfig>(workspacePath);
  if (!workspace) {
    throw new Error("current directory is not initialized for aw; run `aw init` or `aw run` first");
  }

  const baseURL = (workspace.aweb_url || "").trim();
  const activeTeam = (workspace.active_team || "").trim();
  const membership = (workspace.memberships || []).find((item) => (item.team_id || "").trim() === activeTeam);
  const teamID = activeTeam;
  const alias = ((membership?.alias || "").trim());
  if (!baseURL || !teamID || !membership || !alias) {
    throw new Error("worktree workspace binding is missing aweb_url, active_team, or the active membership alias");
  }

  const signingKey = await loadSigningKey(signingKeyPath);
  const certificate = await loadActiveTeamCertificate(workdir, teamID);
  const identity = await readYAML<IdentityConfig>(identityPath);
  const did = computeDIDKey(ed.getPublicKey(signingKey));
  const stableID = ((identity?.stable_id || "").trim()) || (certificate.member_did_aw || "").trim();
  const address = ((identity?.address || "").trim()) || (certificate.member_address || "").trim();

  if ((identity?.did || "").trim() && did !== identity?.did?.trim()) {
    throw new Error("identity.yaml did does not match .aw/signing.key");
  }
  if ((certificate.member_did_key || "").trim() !== did) {
    throw new Error("team certificate member_did_key does not match .aw/signing.key");
  }
  if ((certificate.team_id || "").trim() !== teamID) {
    throw new Error(`workspace.yaml active_team does not match certificate for ${teamID}`);
  }
  if ((certificate.alias || "").trim() !== alias) {
    throw new Error("workspace.yaml active membership alias does not match the team certificate");
  }

  return {
    baseURL,
    did,
    stableID,
    address,
    alias,
    teamID,
    signingKey,
    teamCertificateHeader: encodeTeamCertificateHeader(certificate),
  };
}

async function loadActiveTeamCertificate(workdir: string, activeTeam: string): Promise<TeamCertificate> {
  const certsDir = join(workdir, ".aw", "team-certs");
  const files = await readdir(certsDir);
  for (const file of files) {
    if (!file.endsWith(".pem")) continue;
    const cert = await loadTeamCertificate(join(certsDir, file));
    if ((cert.team_id || "").trim() === activeTeam) {
      return cert;
    }
  }
  throw new Error(`No team certificate found for active team ${activeTeam} in ${certsDir}`);
}

async function readYAML<T>(path: string): Promise<T | null> {
  try {
    const content = await readFile(path, "utf-8");
    return (yaml.load(content) as T) || null;
  } catch {
    return null;
  }
}
