import { readFile } from "node:fs/promises";
import { join } from "node:path";
import yaml from "js-yaml";

export interface AgentConfig {
  baseURL: string;
  apiKey: string;
  did: string;
  stableID: string;
  address: string;
  alias: string;
  projectSlug: string;
}

interface WorkspaceConfig {
  server_url?: string;
  api_key?: string;
  identity_handle?: string;
  namespace_slug?: string;
  did?: string;
  stable_id?: string;
  alias?: string;
  project_slug?: string;
}

interface IdentityConfig {
  did?: string;
  stable_id?: string;
  address?: string;
}

export async function resolveConfig(workdir: string): Promise<AgentConfig> {
  const workspacePath = join(workdir, ".aw", "workspace.yaml");
  const identityPath = join(workdir, ".aw", "identity.yaml");

  const workspace = await readYAML<WorkspaceConfig>(workspacePath);
  if (!workspace) {
    throw new Error("current directory is not initialized for aw; run `aw init` or `aw run` first");
  }

  const baseURL = (workspace.server_url || "").trim();
  const apiKey = (workspace.api_key || "").trim();
  if (!baseURL || !apiKey) {
    throw new Error("worktree workspace binding is missing server_url or api_key");
  }

  const identity = await readYAML<IdentityConfig>(identityPath);
  const alias = ((workspace.identity_handle || workspace.alias || "").trim())
    || handleFromAddress((identity?.address || "").trim());
  const projectSlug = (workspace.project_slug || "").trim();
  const namespaceSlug = ((workspace.namespace_slug || "").trim()) || projectSlug;
  const address = ((identity?.address || "").trim())
    || deriveAddress(namespaceSlug, projectSlug, alias);

  return {
    baseURL,
    apiKey,
    did: ((identity?.did || "").trim()) || (workspace.did || "").trim(),
    stableID: ((identity?.stable_id || "").trim()) || (workspace.stable_id || "").trim(),
    address,
    alias,
    projectSlug,
  };
}

function deriveAddress(namespaceSlug: string, projectSlug: string, alias: string): string {
  const handle = alias.trim();
  if (!handle) return "";
  const namespace = namespaceSlug.trim();
  if (namespace) return `${namespace}/${handle}`;
  const project = projectSlug.trim();
  if (project) return `${project}/${handle}`;
  return handle;
}

function handleFromAddress(address: string): string {
  const trimmed = address.trim();
  if (!trimmed) return "";
  const slash = trimmed.lastIndexOf("/");
  if (slash < 0) return trimmed;
  return trimmed.slice(slash + 1).trim();
}

async function readYAML<T>(path: string): Promise<T | null> {
  try {
    const content = await readFile(path, "utf-8");
    return (yaml.load(content) as T) || null;
  } catch {
    return null;
  }
}
