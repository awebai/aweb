import { describe, expect, test } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { fetchHistory } from "../src/api/chat.js";
import { fetchInbox } from "../src/api/mail.js";
import { canonicalJSON, signMessage, type MessageEnvelope } from "../src/identity/signing.js";

const testDir = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(testDir, "vectors.json"), "utf-8"),
) as {
  seed: string;
  did: string;
  stableID: string;
};

function b64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

function mailEnvelope(overrides: Partial<MessageEnvelope> = {}): MessageEnvelope {
  return {
    from: "acme.com/alice",
    from_did: vectors.did,
    to: "acme.com/bob",
    to_did: "did:key:z6MkBob",
    type: "mail",
    subject: "hello",
    body: "world",
    timestamp: "2025-01-01T00:00:00Z",
    from_stable_id: vectors.stableID,
    message_id: "mail-1",
    ...overrides,
  };
}

function chatEnvelope(overrides: Partial<MessageEnvelope> = {}): MessageEnvelope {
  return {
    from: "acme.com/alice",
    from_did: vectors.did,
    to: "acme.com/bob",
    to_did: "did:key:z6MkBob",
    type: "chat",
    subject: "",
    body: "hello chat",
    timestamp: "2025-01-01T00:00:00Z",
    from_stable_id: vectors.stableID,
    message_id: "chat-1",
    ...overrides,
  };
}

describe("conversation-bound verification", () => {
  test("downgrades legacy mail signatures that do not bind the conversation id", async () => {
    const env = mailEnvelope();
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const client = {
      get: async () => ({
        messages: [{
          message_id: env.message_id,
          conversation_id: "conv-1",
          from_agent_id: "agent-alice",
          from_alias: "alice",
          from_address: env.from,
          to_alias: "bob",
          to_address: env.to,
          subject: env.subject,
          body: env.body,
          priority: "normal",
          created_at: env.timestamp,
          from_did: env.from_did,
          to_did: env.to_did,
          from_stable_id: env.from_stable_id,
          signature,
          signing_key_id: env.from_did,
        }],
      }),
    };

    const messages = await fetchInbox(client as never);

    expect(messages[0].verification_status).toBe("verified_legacy");
  });

  test("requires signed mail payloads to bind the same conversation id", async () => {
    const env = mailEnvelope({ conversation_id: "conv-1" });
    const signedPayload = canonicalJSON(env);
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const legacyEnv = mailEnvelope({ message_id: "mail-legacy" });
    const legacySignedPayload = canonicalJSON(legacyEnv);
    const legacySignature = await signMessage(b64ToBytes(vectors.seed), legacyEnv);
    const client = {
      get: async () => ({
        messages: [{
          message_id: env.message_id,
          conversation_id: "conv-1",
          from_agent_id: "agent-alice",
          from_alias: "alice",
          from_address: env.from,
          to_alias: "bob",
          to_address: env.to,
          subject: env.subject,
          body: env.body,
          priority: "normal",
          created_at: env.timestamp,
          from_did: env.from_did,
          to_did: env.to_did,
          from_stable_id: env.from_stable_id,
          signature,
          signing_key_id: env.from_did,
          signed_payload: signedPayload,
        }, {
          message_id: "mail-2",
          conversation_id: "conv-replay",
          from_agent_id: "agent-alice",
          from_alias: "alice",
          from_address: env.from,
          to_alias: "bob",
          to_address: env.to,
          subject: env.subject,
          body: env.body,
          priority: "normal",
          created_at: env.timestamp,
          from_did: env.from_did,
          to_did: env.to_did,
          from_stable_id: env.from_stable_id,
          signature,
          signing_key_id: env.from_did,
          signed_payload: signedPayload,
        }, {
          message_id: "mail-legacy",
          conversation_id: "conv-1",
          from_agent_id: "agent-alice",
          from_alias: "alice",
          from_address: legacyEnv.from,
          to_alias: "bob",
          to_address: legacyEnv.to,
          subject: legacyEnv.subject,
          body: legacyEnv.body,
          priority: "normal",
          created_at: legacyEnv.timestamp,
          from_did: legacyEnv.from_did,
          to_did: legacyEnv.to_did,
          from_stable_id: legacyEnv.from_stable_id,
          signature: legacySignature,
          signing_key_id: legacyEnv.from_did,
          signed_payload: legacySignedPayload,
        }],
      }),
    };

    const messages = await fetchInbox(client as never, true, 50);

    expect(messages[0].verification_status).toBe("verified");
    expect(messages[1].verification_status).toBe("failed");
    expect(messages[2].verification_status).toBe("verified_legacy");
  });

  test("downgrades legacy chat signatures that do not bind the conversation id", async () => {
    const env = chatEnvelope();
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const client = {
      get: async () => ({
        messages: [{
          message_id: env.message_id,
          conversation_id: "chat-conv-1",
          from_agent: "alice",
          from_address: env.from,
          to_address: env.to,
          body: env.body,
          timestamp: env.timestamp,
          sender_leaving: false,
          from_did: env.from_did,
          to_did: env.to_did,
          from_stable_id: env.from_stable_id,
          signature,
          signing_key_id: env.from_did,
        }],
      }),
    };

    const messages = await fetchHistory(client as never, "chat-conv-1");

    expect(messages[0].verification_status).toBe("verified_legacy");
  });
});
