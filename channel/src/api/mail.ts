import type { APIClient } from "./client.js";
import type { MessageEnvelope, VerificationStatus } from "../identity/signing.js";
import { verifyMessage, verifySignedPayload } from "../identity/signing.js";

export interface InboxMessage {
  message_id: string;
  from_agent_id: string;
  from_alias: string;
  to_alias?: string;
  from_address?: string;
  to_address?: string;
  subject: string;
  body: string;
  priority: string;
  thread_id?: string;
  read_at?: string;
  created_at: string;
  from_did?: string;
  to_did?: string;
  from_stable_id?: string;
  to_stable_id?: string;
  signature?: string;
  signing_key_id?: string;
  signed_payload?: string;
  verification_status?: VerificationStatus;
}

export async function fetchInbox(
  client: APIClient,
  unreadOnly: boolean = true,
  limit: number = 50,
): Promise<InboxMessage[]> {
  const params = new URLSearchParams();
  if (unreadOnly) params.set("unread_only", "true");
  if (limit > 0) params.set("limit", String(limit));

  const resp = await client.get<{ messages: InboxMessage[] }>(
    `/v1/messages/inbox?${params}`,
  );

  // Verify signatures on received messages
  for (const msg of resp.messages) {
    msg.verification_status = await verifyInboxMessage(msg);
  }

  return resp.messages;
}

export async function ackMessage(
  client: APIClient,
  messageId: string,
): Promise<void> {
  await client.post(`/v1/messages/${encodeURIComponent(messageId)}/ack`);
}

async function verifyInboxMessage(msg: InboxMessage): Promise<VerificationStatus> {
  if (msg.signed_payload && msg.signature && msg.from_did) {
    return verifySignedPayload(
      msg.signed_payload,
      msg.signature,
      msg.from_did,
      msg.signing_key_id || "",
    );
  }

  const from = msg.from_address || msg.from_alias;
  const to = msg.to_address || msg.to_alias || "";

  const env: MessageEnvelope = {
    from,
    from_did: msg.from_did || "",
    to,
    to_did: msg.to_did || "",
    type: "mail",
    subject: msg.subject,
    body: msg.body,
    timestamp: msg.created_at,
    from_stable_id: msg.from_stable_id,
    to_stable_id: msg.to_stable_id,
    message_id: msg.message_id,
    signature: msg.signature,
    signing_key_id: msg.signing_key_id,
  };

  return verifyMessage(env);
}
