import { describe, expect, test, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  dispatchAgentEvent,
  PinStore,
  type AgentEvent,
  type ChannelAwakening,
  type SenderTrustManager,
} from "../../channel-core/src/index.js";
import { canonicalJSON, signMessage, type MessageEnvelope } from "../../channel-core/src/identity/signing.js";

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

describe("channel-core dispatchAgentEvent", () => {
  const self = {
    alias: "eve",
    address: "acme.com/eve",
    did: "did:key:self-eve",
    stableID: "did:aw:self-eve",
  };

  const trust = {
    normalizeTrust: vi.fn(async () => ({ status: "verified", stored: false })),
  } as unknown as SenderTrustManager;

  test("acks mail after channel delivery succeeds", async () => {
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-1",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "world",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-1" } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "world",
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-1/ack");
  });

  test("marks chat read after channel delivery succeeds", async () => {
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-1",
          conversation_id: "sess-1",
          from_agent: "alice",
          from_address: "acme.com/alice",
          body: "hello",
          timestamp: "2025-01-01T00:00:00Z",
          sender_leaving: false,
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: "sess-1",
        conversation_id: "sess-1",
        message_id: "chat-1",
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "hello",
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/chat/sessions/sess-1/read", { up_to_message_id: "chat-1" });
  });

  test("mail trust uses signed-payload did:key when envelope carries stable did:aw", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/aida",
      from_did: vectors.did,
      to: self.address,
      to_did: self.did,
      type: "mail",
      subject: "hello",
      body: "signed mail",
      timestamp: "2025-01-01T00:00:00Z",
      from_stable_id: vectors.stableID,
      to_stable_id: self.stableID,
      message_id: "mail-stable-envelope",
      conversation_id: "conv-mail-stable",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const normalizeTrust = vi.fn(async (
      _store,
      status,
      _rawAddress,
      fromDID,
      fromStableID,
      toDID,
      toStableID,
    ) => {
      expect(status).toBe("verified");
      expect(fromDID).toBe(vectors.did);
      expect(fromStableID).toBe(vectors.stableID);
      expect(toDID).toBe(self.did);
      expect(toStableID).toBe(self.stableID);
      return { status, stored: false };
    });
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: env.message_id,
          conversation_id: env.conversation_id,
          from_agent_id: "agent-aida",
          from_alias: "aida",
          from_address: env.from,
          to_alias: self.alias,
          subject: env.subject,
          body: env.body,
          priority: "normal",
          created_at: env.timestamp,
          from_did: vectors.stableID,
          from_stable_id: vectors.stableID,
          to_did: self.stableID,
          to_stable_id: self.stableID,
          signature,
          signing_key_id: vectors.did,
          signed_payload: canonicalJSON(env),
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: { normalizeTrust } as unknown as SenderTrustManager,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: env.message_id } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "signed mail",
      meta: expect.objectContaining({
        trust_status: "verified",
        verified: "true",
      }),
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-stable-envelope/ack");
  });

  test("chat trust uses signed-payload did:key when envelope carries stable did:aw", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/ama",
      from_did: vectors.did,
      to: self.address,
      to_did: self.did,
      type: "chat",
      subject: "",
      body: "signed chat",
      timestamp: "2025-01-01T00:00:00Z",
      from_stable_id: vectors.stableID,
      to_stable_id: self.stableID,
      message_id: "chat-stable-envelope",
      conversation_id: "sess-stable",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const normalizeTrust = vi.fn(async (
      _store,
      status,
      _rawAddress,
      fromDID,
      fromStableID,
      toDID,
      toStableID,
    ) => {
      expect(status).toBe("verified");
      expect(fromDID).toBe(vectors.did);
      expect(fromStableID).toBe(vectors.stableID);
      expect(toDID).toBe(self.did);
      expect(toStableID).toBe(self.stableID);
      return { status, stored: false };
    });
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: env.message_id,
          conversation_id: env.conversation_id,
          from_agent: "ama",
          from_address: env.from,
          to_address: env.to,
          body: env.body,
          timestamp: env.timestamp,
          sender_leaving: false,
          from_did: vectors.stableID,
          from_stable_id: vectors.stableID,
          to_did: self.stableID,
          to_stable_id: self.stableID,
          signature,
          signing_key_id: vectors.did,
          signed_payload: canonicalJSON(env),
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: { normalizeTrust } as unknown as SenderTrustManager,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: env.conversation_id,
        conversation_id: env.conversation_id,
        message_id: env.message_id,
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "signed chat",
      meta: expect.objectContaining({
        trust_status: "verified",
        verified: "true",
      }),
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/chat/sessions/sess-stable/read", { up_to_message_id: "chat-stable-envelope" });
  });
});
