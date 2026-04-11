import type { APIClient } from "./client.js";
import type { MessageEnvelope, VerificationStatus } from "../identity/signing.js";
import type { ReplacementAnnouncement, RotationAnnouncement } from "../identity/trust.js";
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
  rotation_announcement?: RotationAnnouncement;
  replacement_announcement?: ReplacementAnnouncement;
  is_contact?: boolean;
  verification_status?: VerificationStatus;
}

export async function fetchInbox(
  client: APIClient,
  unreadOnly: boolean = true,
  limit: number = 50,
  messageID?: string,
): Promise<InboxMessage[]> {
  const params = new URLSearchParams();
  if (unreadOnly) params.set("unread_only", "true");
  if (limit > 0) params.set("limit", String(limit));
  if ((messageID || "").trim()) params.set("message_id", messageID!.trim());

  const resp = await client.get<{ messages: InboxMessage[] }>(
    `/v1/messages/inbox?${params}`,
  );

  // Verify signatures on received messages
  for (const msg of resp.messages) {
    hydrateAddressesFromSignedPayload(msg);
    msg.verification_status = await verifyInboxMessage(msg);
  }

  return resp.messages;
}

function hydrateAddressesFromSignedPayload(msg: InboxMessage): void {
  if (!msg.signed_payload) return;
  try {
    const payload = JSON.parse(msg.signed_payload) as {
      from?: string;
      to?: string;
      from_did?: string;
      to_did?: string;
      from_stable_id?: string;
      to_stable_id?: string;
    };
    if (typeof payload.from_did === "string" && payload.from_did.trim()) {
      msg.from_did = payload.from_did;
    }
    if (typeof payload.to_did === "string" && payload.to_did.trim()) {
      msg.to_did = payload.to_did;
    }
    if (!msg.from_stable_id && typeof payload.from_stable_id === "string") {
      msg.from_stable_id = payload.from_stable_id;
    }
    if (!msg.to_stable_id && typeof payload.to_stable_id === "string") {
      msg.to_stable_id = payload.to_stable_id;
    }
    if (!msg.from_address && typeof payload.from === "string") {
      msg.from_address = payload.from;
    }
    if (!msg.to_address && typeof payload.to === "string") {
      msg.to_address = payload.to;
    }
  } catch {
    // Signature verification will fail if the payload is malformed.
  }
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
