import { readFile } from "node:fs/promises";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import yaml from "js-yaml";
import { loadTeamCertificate, encodeTeamCertificateHeader } from "./identity/certificate.js";
import { computeDIDKey } from "./identity/did.js";
import { loadSigningKey } from "./identity/keys.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface AgentConfig {
  baseURL: string;
  did: string;
  stableID: string;
  address: string;
  alias: string;
  teamAddress: string;
  signingKey: Uint8Array;
  teamCertificateHeader: string;
}

interface WorkspaceConfig {
  aweb_url?: string;
  team_address?: string;
  alias?: string;
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
  const certificatePath = join(workdir, ".aw", "team-cert.pem");

  const workspace = await readYAML<WorkspaceConfig>(workspacePath);
  if (!workspace) {
    throw new Error("current directory is not initialized for aw; run `aw init` or `aw run` first");
  }

  const baseURL = (workspace.aweb_url || "").trim();
  const teamAddress = (workspace.team_address || "").trim();
  const alias = (workspace.alias || "").trim();
  if (!baseURL || !teamAddress || !alias) {
    throw new Error("worktree workspace binding is missing aweb_url, team_address, or alias");
  }

  const signingKey = await loadSigningKey(signingKeyPath);
  const certificate = await loadTeamCertificate(certificatePath);
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
  if ((certificate.team || "").trim() !== teamAddress) {
    throw new Error("workspace.yaml team_address does not match .aw/team-cert.pem");
  }
  if ((certificate.alias || "").trim() !== alias) {
    throw new Error("workspace.yaml alias does not match .aw/team-cert.pem");
  }

  return {
    baseURL,
    did,
    stableID,
    address,
    alias,
    teamAddress,
    signingKey,
    teamCertificateHeader: encodeTeamCertificateHeader(certificate),
  };
}

async function readYAML<T>(path: string): Promise<T | null> {
  try {
    const content = await readFile(path, "utf-8");
    return (yaml.load(content) as T) || null;
  } catch {
    return null;
  }
}
