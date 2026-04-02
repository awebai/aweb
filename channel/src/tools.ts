import type { APIClient } from "./api/client.js";
import { fetchInbox, sendMail, ackMessage } from "./api/mail.js";
import { fetchPending, createSession, sendMessage, markRead } from "./api/chat.js";
import { canonicalJSON, signMessage, type MessageEnvelope } from "./identity/signing.js";

interface SigningContext {
  seed: Uint8Array | null;
  did: string;
  stableID: string;
  alias: string;
  projectSlug: string;
}

export const TOOL_DEFINITIONS = [
  {
    name: "mail_send",
    description: "Send async mail to another agent",
    inputSchema: {
      type: "object" as const,
      properties: {
        to_alias: { type: "string", description: "Recipient agent alias" },
        body: { type: "string", description: "Message body" },
        subject: { type: "string", description: "Message subject" },
        priority: {
          type: "string",
          enum: ["low", "normal", "high", "urgent"],
          description: "Message priority",
        },
      },
      required: ["to_alias", "body"],
    },
  },
  {
    name: "mail_ack",
    description: "Acknowledge a received mail message",
    inputSchema: {
      type: "object" as const,
      properties: {
        message_id: { type: "string", description: "ID of the message to acknowledge" },
      },
      required: ["message_id"],
    },
  },
  {
    name: "mail_inbox",
    description: "Fetch unread mail messages",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "chat_start",
    description: "Start a new chat conversation with another agent",
    inputSchema: {
      type: "object" as const,
      properties: {
        to_alias: { type: "string", description: "Recipient agent alias" },
        body: { type: "string", description: "First message" },
        leaving: {
          type: "boolean",
          description: "If true, send without waiting for reply (send-and-leave)",
        },
      },
      required: ["to_alias", "body"],
    },
  },
  {
    name: "chat_reply",
    description: "Reply in an existing chat session",
    inputSchema: {
      type: "object" as const,
      properties: {
        session_id: { type: "string", description: "Chat session ID from the channel event" },
        body: { type: "string", description: "Reply message" },
      },
      required: ["session_id", "body"],
    },
  },
  {
    name: "chat_mark_read",
    description: "Mark chat messages as read up to a given message",
    inputSchema: {
      type: "object" as const,
      properties: {
        session_id: { type: "string", description: "Chat session ID" },
        up_to_message_id: { type: "string", description: "Mark all messages up to this ID as read" },
      },
      required: ["session_id", "up_to_message_id"],
    },
  },
  {
    name: "chat_pending",
    description: "Fetch pending chat conversations",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
];

async function buildSigningFields(
  ctx: SigningContext,
  env: MessageEnvelope,
): Promise<Record<string, string>> {
  if (!ctx.seed || !ctx.did) return {};

  const signed: MessageEnvelope = {
    ...env,
    from_did: ctx.did,
    from_stable_id: ctx.stableID || undefined,
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    message_id: crypto.randomUUID(),
  };

  const sig = await signMessage(ctx.seed, signed);

  return {
    from_did: ctx.did,
    from_stable_id: ctx.stableID || "",
    signature: sig,
    signing_key_id: ctx.did,
    timestamp: signed.timestamp,
    message_id: signed.message_id!,
    signed_payload: canonicalJSON(signed),
  };
}

export async function handleToolCall(
  name: string,
  args: Record<string, unknown>,
  client: APIClient,
  signing: SigningContext,
): Promise<{ content: { type: "text"; text: string }[] }> {
  switch (name) {
    case "mail_send": {
      const toAlias = args.to_alias as string;
      const body = args.body as string;
      const subject = (args.subject as string) || "";
      const priority = (args.priority as string) || "normal";

      const from = signing.alias || "";
      const sigFields = await buildSigningFields(signing, {
        from, from_did: "", to: toAlias, to_did: "",
        type: "mail", subject, body, timestamp: "",
      });

      const resp = await sendMail(client, {
        to_alias: toAlias, body, subject,
        priority: priority as "low" | "normal" | "high" | "urgent",
        ...sigFields,
      });

      return { content: [{ type: "text", text: `sent: ${resp.message_id}` }] };
    }

    case "mail_ack": {
      await ackMessage(client, args.message_id as string);
      return { content: [{ type: "text", text: "acknowledged" }] };
    }

    case "mail_inbox": {
      const messages = await fetchInbox(client, true);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(messages.map((msg) => ({
            from: msg.from_alias || msg.from_address || msg.from_agent_id,
            subject: msg.subject,
            body: msg.body,
            priority: msg.priority,
            message_id: msg.message_id,
          })), null, 2),
        }],
      };
    }

    case "chat_start": {
      const toAlias = args.to_alias as string;
      const body = args.body as string;
      const leaving = (args.leaving as boolean) || false;

      const from = signing.alias || "";
      const sigFields = await buildSigningFields(signing, {
        from, from_did: "", to: toAlias, to_did: "",
        type: "chat", subject: "", body, timestamp: "",
      });

      const resp = await createSession(client, [toAlias], body, leaving, sigFields);
      return {
        content: [{
          type: "text",
          text: `session: ${resp.session_id}, message: ${resp.message_id}`,
        }],
      };
    }

    case "chat_reply": {
      const sessionId = args.session_id as string;
      const body = args.body as string;

      const from = signing.alias || "";
      const sigFields = await buildSigningFields(signing, {
        from, from_did: "", to: "", to_did: "",
        type: "chat", subject: "", body, timestamp: "",
      });

      const resp = await sendMessage(client, sessionId, { body, ...sigFields });
      return { content: [{ type: "text", text: `sent: ${resp.message_id}` }] };
    }

    case "chat_mark_read": {
      await markRead(client, args.session_id as string, args.up_to_message_id as string);
      return { content: [{ type: "text", text: "marked read" }] };
    }

    case "chat_pending": {
      const pending = await fetchPending(client);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(pending.map((item) => ({
            session_id: item.session_id,
            participants: item.participants,
            unread_count: item.unread_count,
            sender_waiting: item.sender_waiting,
            last_message: item.last_message,
          })), null, 2),
        }],
      };
    }

    default:
      throw new Error(`unknown tool: ${name}`);
  }
}
