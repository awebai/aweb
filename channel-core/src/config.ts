import { lstatSync, type Stats } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, normalize, parse, relative, resolve, sep } from "node:path";
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
  registryURL: string;
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
  memberships?: WorkspaceMembership[];
  team_address?: string;
}

interface TeamMembership {
  team_id?: string;
  alias?: string;
  cert_path?: string;
  joined_at?: string;
}

interface TeamStateConfig {
  active_team?: string;
  memberships?: TeamMembership[];
}

interface IdentityConfig {
  did?: string;
  stable_id?: string;
  address?: string;
  registry_url?: string;
}

interface IdentityHomeSelection {
  root: string;
  external: boolean;
}

function selectIdentityHome(workdir: string): IdentityHomeSelection {
  const configuredHome = (process.env.AWEB_IDENTITY_HOME || "").trim();
  if (!configuredHome) return { root: join(workdir, ".aw"), external: false };
  if (!isAbsolute(configuredHome)) {
    throw new Error("AWEB_IDENTITY_HOME must be an absolute path");
  }
  const root = normalize(configuredHome);
  preflightDirectory(root, "identity home");
  return { root, external: true };
}

export async function resolveConfig(workdir: string): Promise<AgentConfig> {
  const identityHome = selectIdentityHome(workdir);
  const workspacePath = join(identityHome.root, "workspace.yaml");
  const teamsPath = join(identityHome.root, "teams.yaml");
  const identityPath = join(identityHome.root, "identity.yaml");
  const signingKeyPath = join(identityHome.root, "signing.key");

  if (identityHome.external) preflightFile(workspacePath, "workspace config");
  const workspace = await readYAML<WorkspaceConfig>(workspacePath);
  if (!workspace) {
    throw new Error("current directory is not initialized for aw; run `aw init` or `aw run` first");
  }

  const baseURL = (workspace.aweb_url || "").trim();
  const legacyTeamAddress = (workspace.team_address || "").trim();
  if (legacyTeamAddress && !Array.isArray(workspace.memberships)) {
    throw new Error(
      "This workspace is on the legacy single-team shape (.aw/workspace.yaml has team_address but no memberships). Run aw workspace migrate-multi-team to convert, then retry.",
    );
  }

  if (identityHome.external) preflightFile(teamsPath, "team state");
  const teamState = await readYAML<TeamStateConfig>(teamsPath);
  if (!teamState) {
    throw new Error("worktree team state is missing .aw/teams.yaml; run `aw init` or `aw id team add` first");
  }
  const activeTeam = (teamState.active_team || "").trim();
  const teamMembership = (teamState.memberships || []).find((item) => (item.team_id || "").trim() === activeTeam);
  const workspaceMembership = (workspace.memberships || []).find((item) => (item.team_id || "").trim() === activeTeam);
  const teamID = activeTeam;
  const alias = ((teamMembership?.alias || "").trim());
  const certPath = ((teamMembership?.cert_path || "").trim());
  if (!baseURL || !teamID || !teamMembership || !workspaceMembership || !alias || !certPath) {
    throw new Error("worktree workspace binding is missing aweb_url, active_team, or the active membership alias");
  }

  if (identityHome.external) preflightFile(signingKeyPath, "signing key");
  const signingKey = await loadSigningKey(signingKeyPath);
  const certificate = await loadConfiguredTeamCertificate(identityHome, teamID, certPath);
  if (identityHome.external) preflightFile(identityPath, "identity config");
  const identity = await readYAML<IdentityConfig>(identityPath);
  const did = computeDIDKey(ed.getPublicKey(signingKey));
  const identityStableID = (identity?.stable_id || "").trim();
  const certificateStableID = (certificate.member_did_aw || "").trim();
  const stableID = certificateStableID || identityStableID;
  const address = ((certificate.member_address || "").trim()) || ((identity?.address || "").trim());
  const registryURL = (identity?.registry_url || "").trim();

  if ((identity?.did || "").trim() && did !== identity?.did?.trim()) {
    throw new Error("identity.yaml did does not match .aw/signing.key");
  }
  if ((certificate.member_did_key || "").trim() !== did) {
    throw new Error("team certificate member_did_key does not match .aw/signing.key");
  }
  if ((certificate.team_id || "").trim() !== teamID) {
    throw new Error(`team certificate does not match active team ${teamID}`);
  }
  if ((certificate.alias || "").trim() !== alias) {
    throw new Error("active membership alias does not match the team certificate");
  }

  return {
    baseURL,
    did,
    stableID,
    address,
    alias,
    teamID,
    registryURL,
    signingKey,
    teamCertificateHeader: encodeTeamCertificateHeader(certificate),
  };
}

async function loadConfiguredTeamCertificate(
  identityHome: IdentityHomeSelection,
  activeTeam: string,
  certPath: string,
): Promise<TeamCertificate> {
  const path = identityHome.external
    ? resolveExternalCertificatePath(identityHome.root, certPath)
    : join(identityHome.root, certPath);
  try {
    return await loadTeamCertificate(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
    return loadActiveTeamCertificate(identityHome, activeTeam);
  }
}

async function loadActiveTeamCertificate(identityHome: IdentityHomeSelection, activeTeam: string): Promise<TeamCertificate> {
  const certsDir = join(identityHome.root, "team-certs");
  if (identityHome.external) preflightDirectory(certsDir, "team certificate directory");
  let files: string[];
  try {
    files = await readdir(certsDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        `No .aw/team-certs directory found at ${certsDir}. Run aw workspace migrate-multi-team to convert a legacy workspace, or aw init to create a new one.`,
      );
    }
    throw new Error(`Failed to read team certificates from ${certsDir}: ${String(error)}`);
  }
  for (const file of files) {
    if (!file.endsWith(".pem")) continue;
    const path = join(certsDir, file);
    if (identityHome.external) preflightFile(path, "team certificate");
    const cert = await loadTeamCertificate(path);
    if ((cert.team_id || "").trim() === activeTeam) {
      return cert;
    }
  }
  throw new Error(`No team certificate found for active team ${activeTeam} in ${certsDir}`);
}

function resolveExternalCertificatePath(identityHome: string, storedPath: string): string {
  let certificatePath = storedPath.trim();
  if (certificatePath.startsWith(".aw/")) certificatePath = certificatePath.slice(4);
  if (!certificatePath || isAbsolute(certificatePath) || certificatePath.includes("\\")) {
    throw new Error(`certificate path must be relative to AWEB_IDENTITY_HOME: ${JSON.stringify(storedPath)}`);
  }

  const path = resolve(identityHome, certificatePath);
  const rel = relative(identityHome, path);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new Error(`certificate path escapes AWEB_IDENTITY_HOME: ${JSON.stringify(storedPath)}`);
  }
  preflightFile(path, "team certificate");
  return path;
}

function preflightDirectory(path: string, label: string): void {
  const root = parse(path).root;
  const parts = relative(root, path).split(sep).filter(Boolean);
  let current = root;
  for (let index = 0; index < parts.length; index += 1) {
    current = join(current, parts[index]);
    const stat = lstatIfExists(current);
    if (!stat) return;
    if (stat.isSymbolicLink()) {
      const kind = index === parts.length - 1 ? "" : " parent";
      throw new Error(`${label}${kind} ${current} must not be a symlink`);
    }
    if (!stat.isDirectory()) {
      const kind = index === parts.length - 1 ? "" : " parent";
      throw new Error(`${label}${kind} ${current} must be a directory`);
    }
  }
}

function preflightFile(path: string, label: string): void {
  preflightDirectory(dirname(path), label);
  const stat = lstatIfExists(path);
  if (!stat) return;
  if (stat.isSymbolicLink()) throw new Error(`${label} ${path} must not be a symlink`);
  if (!stat.isFile()) throw new Error(`${label} ${path} must be a regular file`);
}

function lstatIfExists(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function readYAML<T>(path: string): Promise<T | null> {
  try {
    const content = await readFile(path, "utf-8");
    return (yaml.load(content) as T) || null;
  } catch {
    return null;
  }
}
