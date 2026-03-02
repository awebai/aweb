import { createHmac } from "crypto";
import { randomUUID } from "crypto";
import { config } from "./config.js";
import type { AdminMessage, AdminSession } from "./types.js";

/**
 * Build auth headers. Supports two modes:
 * 1. Internal HMAC auth (in-cluster) — BEADHUB_INTERNAL_AUTH_SECRET + projectId
 * 2. Bearer token — BEADHUB_API_KEY (aweb per-workspace key)
 *
 * @param projectId - Project UUID to scope the request to. Falls back to BEADHUB_PROJECT_ID.
 */
function authHeaders(projectId?: string): Record<string, string> {
  const { internalAuthSecret, projectId: defaultProjectId, apiKey } = config.beadhub;
  const resolvedProjectId = projectId || defaultProjectId;

  if (internalAuthSecret && resolvedProjectId) {
    // Internal proxy auth: HMAC-signed headers
    const principalType = "k";
    const principalId = randomUUID();
    const actorId = randomUUID();
    const msg = `v2:${resolvedProjectId}:${principalType}:${principalId}:${actorId}`;
    const sig = createHmac("sha256", internalAuthSecret).update(msg).digest("hex");
    return {
      "X-BH-Auth": `${msg}:${sig}`,
      "X-Project-ID": resolvedProjectId,
      "X-API-Key": principalId,
      "X-Aweb-Actor-ID": actorId,
    };
  }

  if (apiKey) {
    return { "Authorization": `Bearer ${apiKey}` };
  }

  return {};
}

async function api<T>(path: string, init?: RequestInit & { projectId?: string }): Promise<T> {
  const url = `${config.beadhub.url}${path}`;
  const { projectId, ...fetchInit } = init ?? {};
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...authHeaders(projectId),
    ...(fetchInit?.headers as Record<string, string> | undefined),
  };
  const res = await fetch(url, { ...fetchInit, headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`BeadHub ${init?.method ?? "GET"} ${path} → ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

/** Fetch the last N messages for a session (admin endpoint, no participant check). */
export async function getSessionMessages(
  sessionId: string,
  limit = 50,
  projectId?: string,
): Promise<AdminMessage[]> {
  const data = await api<{ messages: AdminMessage[] }>(
    `/v1/chat/admin/sessions/${sessionId}/messages?limit=${limit}`,
    { projectId },
  );
  return data.messages;
}

/** List all chat sessions in the project. */
export async function listSessions(limit = 200): Promise<AdminSession[]> {
  const data = await api<{ sessions: AdminSession[] }>(
    `/v1/chat/admin/sessions?limit=${limit}`,
  );
  return data.sessions;
}

/** Join a chat session as the bridge's dashboard identity. */
export async function joinSession(
  sessionId: string,
  workspaceId: string,
  alias: string,
): Promise<void> {
  await api(`/v1/chat/admin/sessions/${sessionId}/join`, {
    method: "POST",
    body: JSON.stringify({ workspace_id: workspaceId, alias }),
  });
}

/** Send a message into a chat session as a dashboard user. */
export async function sendMessage(
  sessionId: string,
  body: string,
  workspaceId: string,
  alias: string,
): Promise<string> {
  const data = await api<{ message_id: string }>(
    `/v1/chat/sessions/${sessionId}/messages`,
    {
      method: "POST",
      body: JSON.stringify({ body, workspace_id: workspaceId, alias }),
    },
  );
  return data.message_id;
}

/** Response from POST /v1/chat/sessions (Create Or Send). */
interface CreateSessionResponse {
  session_id: string;
  message_id: string;
  participants: { workspace_id: string; alias: string }[];
}

/**
 * Create or reuse a chat session and send a message to target aliases.
 * Uses Bearer auth (BEADHUB_API_KEY) since the aweb chat endpoint requires
 * workspace-level identity, not HMAC admin auth.
 */
export async function createOrSendChat(
  toAliases: string[],
  message: string,
): Promise<CreateSessionResponse> {
  const { url, apiKey } = config.beadhub;
  if (!apiKey) {
    throw new Error("BEADHUB_API_KEY is required for aweb chat — set it on the bridge deployment");
  }

  const res = await fetch(`${url}/v1/chat/sessions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      to_aliases: toAliases,
      message,
      leaving: true,
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`BeadHub POST /v1/chat/sessions → ${res.status}: ${body}`);
  }

  return res.json() as Promise<CreateSessionResponse>;
}

/** Repo info from the BeadHub repos API. */
interface RepoInfo {
  repo_id: string;
  canonical_origin: string;
  [key: string]: unknown;
}

/** Fetch repos associated with a project. */
export async function getProjectRepos(projectId: string): Promise<RepoInfo[]> {
  const data = await api<{ repos: RepoInfo[] }>(
    `/v1/repos?project_id=${encodeURIComponent(projectId)}`,
    { projectId },
  );
  return data.repos;
}

/**
 * Get or create a dashboard identity for the bridge.
 * Returns { workspace_id, alias }.
 */
export async function getOrCreateBridgeIdentity(): Promise<{
  workspace_id: string;
  alias: string;
}> {
  return api(`/v1/dashboard/identity`, {
    method: "POST",
    body: JSON.stringify({ human_name: "Discord Bridge", alias: "discord-bridge" }),
  });
}
