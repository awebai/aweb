import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import yaml from "js-yaml";

export interface AgentConfig {
  baseURL: string;
  apiKey: string;
  did: string;
  stableID: string;
  address: string; // namespace/alias
  alias: string;
  projectSlug: string;
}

interface GlobalConfig {
  servers?: Record<string, { url?: string }>;
  accounts?: Record<
    string,
    {
      server?: string;
      api_key?: string;
      did?: string;
      stable_id?: string;
      agent_id?: string;
      alias?: string;
      namespace_slug?: string;
      signing_key?: string;
      default_project?: string;
    }
  >;
}

interface WorktreeContext {
  default_account?: string;
  server_accounts?: Record<string, string>;
  client_default_accounts?: Record<string, string>;
}

interface WorkspaceConfig {
  project_slug?: string;
}

/**
 * Resolve agent configuration from the aw config files.
 * Resolution order: worktree context → global config.
 * Reads the same files as the Go aw client.
 */
export async function resolveConfig(
  workdir: string,
): Promise<AgentConfig> {
  const globalPath = process.env.AW_CONFIG_PATH || join(homedir(), ".config", "aw", "config.yaml");
  const contextPath = join(workdir, ".aw", "context");
  const workspacePath = join(workdir, ".aw", "workspace.yaml");

  const globalConfig = await readYAML<GlobalConfig>(globalPath);
  if (!globalConfig?.accounts || Object.keys(globalConfig.accounts).length === 0) {
    throw new Error(`no accounts configured in ${globalPath}`);
  }

  // Determine account name from worktree context or first available
  let accountName: string | undefined;
  const context = await readYAML<WorktreeContext>(contextPath);
  if (context?.default_account) {
    accountName = context.default_account;
  } else if (context?.client_default_accounts?.aw) {
    accountName = context.client_default_accounts.aw;
  }
  if (!accountName) {
    accountName = Object.keys(globalConfig.accounts)[0];
  }

  const account = globalConfig.accounts[accountName];
  if (!account) {
    throw new Error(`account "${accountName}" not found in ${globalPath}`);
  }
  if (!account.api_key) {
    throw new Error(`account "${accountName}" has no api_key`);
  }

  // Resolve server URL
  const serverName = account.server || "default";
  const server = globalConfig.servers?.[serverName];
  const baseURL = server?.url || "https://app.aweb.ai";

  // Resolve address
  const namespace = account.namespace_slug || "";
  const alias = account.alias || "";
  const address = namespace && alias ? `${namespace}/${alias}` : "";

  // Read workspace config for project slug
  const workspace = await readYAML<WorkspaceConfig>(workspacePath);
  const projectSlug = account.default_project || workspace?.project_slug || "";

  return {
    baseURL,
    apiKey: account.api_key,
    did: account.did || "",
    stableID: account.stable_id || "",
    address,
    alias,
    projectSlug,
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
