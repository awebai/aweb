import type { APIClient } from "./client.js";
import type { InboxMessage } from "./mail.js";
import { verifySignedPayload, type MessageEnvelope } from "../identity/signing.js";

export interface RoomMessage extends Omit<InboxMessage, "from_agent_id" | "priority"> {
  team_id: string;
  room_id: string;
  timestamp: string;
}

/** Exact lookup verifies without consuming the recipient's pending notice. */
export async function fetchRoomMessage(client: APIClient, team: string, room: string, id: string): Promise<RoomMessage> {
  const message = await client.get<RoomMessage>(`/v1/room/messages/${encodeURIComponent(id)}`);
  const status = await verifySignedPayload(message.signed_payload || "", message.signature || "", message.from_did || "", message.signing_key_id || "");
  if (status !== "verified") throw new Error("room post signature failed");
  const signed = JSON.parse(message.signed_payload!) as MessageEnvelope;
  if (message.team_id !== team || message.room_id !== room || message.conversation_id !== room || message.message_id !== id
      || signed.type !== "chat" || signed.to !== `team-room:${team}` || signed.conversation_id !== room || signed.message_id !== id
      || signed.to_did || signed.to_stable_id || signed.from_did !== message.from_did || message.signing_key_id !== message.from_did
      || (signed.from_stable_id || "") !== (message.from_stable_id || "") || signed.from !== message.from_alias
      || signed.subject !== message.subject || signed.body !== message.body || signed.timestamp !== message.timestamp
      || (message.from_address && message.from_address !== signed.from)) {
    throw new Error("room post signed bindings failed");
  }
  message.verification_status = status;
  message.projected_from_did = message.from_did;
  message.signed_from = signed.from;
  message.signed_from_team_id = team;
  return message;
}

export async function ackRoomNotice(client: APIClient, id: string): Promise<void> {
  await client.post(`/v1/room/notices/${encodeURIComponent(id)}/ack`, {});
}
