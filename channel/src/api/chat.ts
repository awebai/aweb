import type { APIClient } from "./client.js";
import type { MessageEnvelope, VerificationStatus } from "../identity/signing.js";
import { verifyMessage, verifySignedPayload } from "../identity/signing.js";

export interface ChatMessage {
  message_id: string;
  from_agent: string;
  from_address?: string;
  to_address?: string;
  body: string;
  timestamp: string;
  sender_leaving: boolean;
  from_did?: string;
  to_did?: string;
  from_stable_id?: string;
  to_stable_id?: string;
  signature?: string;
  signing_key_id?: string;
  signed_payload?: string;
  verification_status?: VerificationStatus;
}

export interface ChatPendingItem {
  session_id: string;
  participants: string[];
  last_message: string;
  last_from: string;
  unread_count: number;
  last_activity: string;
  sender_waiting: boolean;
  time_remaining_seconds?: number;
}

export interface ChatCreateResponse {
  session_id: string;
  message_id: string;
  participants: { agent_id: string; alias: string }[];
  sse_url: string;
  targets_connected: string[];
  targets_left: string[];
}

export interface ChatSendRequest {
  body: string;
  hang_on?: boolean;
  from_did?: string;
  to_did?: string;
  from_stable_id?: string;
  signature?: string;
  signing_key_id?: string;
  timestamp?: string;
  message_id?: string;
  signed_payload?: string;
}

export async function fetchPending(
  client: APIClient,
): Promise<ChatPendingItem[]> {
  const resp = await client.get<{ pending: ChatPendingItem[] }>("/v1/chat/pending");
  return resp.pending;
}

export async function fetchHistory(
  client: APIClient,
  sessionId: string,
  unreadOnly: boolean = false,
  limit: number = 50,
): Promise<ChatMessage[]> {
  const params = new URLSearchParams();
  if (unreadOnly) params.set("unread_only", "true");
  if (limit > 0) params.set("limit", String(limit));

  const resp = await client.get<{ messages: ChatMessage[] }>(
    `/v1/chat/sessions/${encodeURIComponent(sessionId)}/messages?${params}`,
  );

  for (const msg of resp.messages) {
    msg.verification_status = await verifyChatMessage(msg);
  }

  return resp.messages;
}

export async function createSession(
  client: APIClient,
  toAliases: string[],
  message: string,
  leaving: boolean = false,
  signingFields?: Record<string, string>,
): Promise<ChatCreateResponse> {
  return client.post<ChatCreateResponse>("/v1/chat/sessions", {
    to_aliases: toAliases,
    message,
    leaving,
    ...signingFields,
  });
}

export async function sendMessage(
  client: APIClient,
  sessionId: string,
  req: ChatSendRequest,
): Promise<{ message_id: string; delivered: boolean }> {
  return client.post(
    `/v1/chat/sessions/${encodeURIComponent(sessionId)}/messages`,
    req,
  );
}

export async function markRead(
  client: APIClient,
  sessionId: string,
  upToMessageId: string,
): Promise<void> {
  await client.post(
    `/v1/chat/sessions/${encodeURIComponent(sessionId)}/read`,
    { up_to_message_id: upToMessageId },
  );
}

async function verifyChatMessage(msg: ChatMessage): Promise<VerificationStatus> {
  if (msg.signed_payload && msg.signature && msg.from_did) {
    return verifySignedPayload(
      msg.signed_payload,
      msg.signature,
      msg.from_did,
      msg.signing_key_id || "",
    );
  }

  const from = msg.from_address || msg.from_agent;

  const env: MessageEnvelope = {
    from,
    from_did: msg.from_did || "",
    to: msg.to_address || "",
    to_did: msg.to_did || "",
    type: "chat",
    subject: "",
    body: msg.body,
    timestamp: msg.timestamp,
    from_stable_id: msg.from_stable_id,
    to_stable_id: msg.to_stable_id,
    message_id: msg.message_id,
    signature: msg.signature,
    signing_key_id: msg.signing_key_id,
  };

  return verifyMessage(env);
}
