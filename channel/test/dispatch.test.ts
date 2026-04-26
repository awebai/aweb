import { describe, expect, test, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AgentEvent } from "../src/api/events.js";
import { PinStore } from "../src/identity/pinstore.js";
import { canonicalJSON, signMessage, type MessageEnvelope } from "../src/identity/signing.js";
import { SenderTrustManager } from "../src/identity/trust.js";
import { dispatchEvent } from "../src/index.js";

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

async function signedInboxMail(messageID: string) {
  const env: MessageEnvelope = {
    from: "acme.com/alice",
    from_did: vectors.did,
    to: "eve",
    to_did: "",
    type: "mail",
    subject: "hello",
    body: "world",
    timestamp: "2025-01-01T00:00:00Z",
    from_stable_id: vectors.stableID,
    message_id: messageID,
  };
  const signature = await signMessage(b64ToBytes(vectors.seed), env);
  return {
    message_id: messageID,
    from_agent_id: "agent-1",
    from_alias: "alice",
    from_address: env.from,
    to_alias: env.to,
    subject: env.subject,
    body: env.body,
    priority: "normal",
    created_at: env.timestamp,
    from_did: env.from_did,
    from_stable_id: env.from_stable_id,
    signature,
    signing_key_id: env.from_did,
  };
}

async function signedInboxMailWithStableRecipient(messageID: string, selfStableID: string) {
  const env: MessageEnvelope = {
    from: "acme.com/alice",
    from_did: vectors.did,
    to: selfStableID,
    to_did: selfStableID,
    type: "mail",
    subject: "stable recipient",
    body: "stable-bound mail",
    timestamp: "2025-01-01T00:00:00Z",
    from_stable_id: vectors.stableID,
    to_stable_id: selfStableID,
    message_id: messageID,
  };
  const signature = await signMessage(b64ToBytes(vectors.seed), env);
  return {
    message_id: messageID,
    from_agent_id: "agent-1",
    from_alias: "alice",
    from_address: env.from,
    to_alias: "eve",
    subject: env.subject,
    body: env.body,
    priority: "normal",
    created_at: env.timestamp,
    from_did: env.from_did,
    from_stable_id: env.from_stable_id,
    to_did: env.to_did,
    to_stable_id: env.to_stable_id,
    signature,
    signing_key_id: env.from_did,
    signed_payload: canonicalJSON(env),
  };
}

describe("dispatchEvent", () => {
  const self = {
    alias: "eve",
    address: "acme.com/eve",
    did: "did:key:self-eve",
    stableID: "did:aw:self-eve",
  };

  test("notifies claim_update events", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };

    await dispatchEvent(
      mcp as never,
      {} as never,
      new PinStore(),
      { normalizeTrust: vi.fn() } as unknown as SenderTrustManager,
      self,
      new Set(),
      {
        type: "claim_update",
        task_id: "aweb-aabz.2",
        title: "Add chat_pending and mail_inbox tools to channel",
        status: "claimed",
      } satisfies AgentEvent,
    );

    expect(notification).toHaveBeenCalledWith({
      method: "notifications/claude/channel",
      params: {
        content: "Add chat_pending and mail_inbox tools to channel",
        meta: {
          type: "claim",
          task_id: "aweb-aabz.2",
          title: "Add chat_pending and mail_inbox tools to channel",
          status: "claimed",
        },
      },
    });
  });

  test("notifies claim_removed events", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };

    await dispatchEvent(
      mcp as never,
      {} as never,
      new PinStore(),
      { normalizeTrust: vi.fn() } as unknown as SenderTrustManager,
      self,
      new Set(),
      {
        type: "claim_removed",
        task_id: "aweb-aabz.2",
      } satisfies AgentEvent,
    );

    expect(notification).toHaveBeenCalledWith({
      method: "notifications/claude/channel",
      params: {
        content: "",
        meta: {
          type: "claim_removed",
          task_id: "aweb-aabz.2",
        },
      },
    });
  });

  test("falls back to TOFU on the public sender address when registry verification is degraded", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({ messages: [await signedInboxMail("msg-degraded")] }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = {
      normalizeTrust: vi.fn(async (_store, status, from, fromDid, fromStableID) => {
        const pinKey = fromStableID || fromDid;
        pinStore.storePin(pinKey, from, "", "");
        const pin = pinStore.pins.get(pinKey)!;
        pin.stable_id = fromStableID;
        pin.did_key = fromDid;
        return { status, stored: true };
      }),
    } as unknown as SenderTrustManager;

    await dispatchEvent(
      mcp as never,
      client as never,
      pinStore,
      trust,
      self,
      new Set(),
      { type: "mail_message", message_id: "msg-degraded" } satisfies AgentEvent,
    );

    expect(notification).toHaveBeenCalledWith({
      method: "notifications/claude/channel",
      params: {
        content: "world",
        meta: {
          type: "mail",
          from: "acme.com/alice",
          message_id: "msg-degraded",
          subject: "hello",
          verified: "true",
        },
      },
    });
    expect(pinStore.addresses.get("acme.com/alice")).toBe(vectors.stableID);
    expect(pinStore.pins.get(vectors.stableID)?.did_key).toBe(vectors.did);
  });

  test("passes the public sender address to trust and notifications when it is present", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({ messages: [await signedInboxMail("msg-local-trust")] }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const normalizeTrust = vi.fn(async () => ({ status: "verified", stored: false }));
    const trust = { normalizeTrust } as unknown as SenderTrustManager;

    await dispatchEvent(
      mcp as never,
      client as never,
      pinStore,
      trust,
      self,
      new Set(),
      { type: "mail_message", message_id: "msg-local-trust" } satisfies AgentEvent,
    );

    expect(normalizeTrust).toHaveBeenCalledWith(
      pinStore,
      "verified",
      "acme.com/alice",
      vectors.did,
      vectors.stableID,
      undefined,
      undefined,
      undefined,
      undefined,
      "acme.com/alice",
    );
    expect(notification).toHaveBeenCalledWith({
      method: "notifications/claude/channel",
      params: {
        content: "world",
        meta: {
          type: "mail",
          from: "acme.com/alice",
          message_id: "msg-local-trust",
          subject: "hello",
          verified: "true",
        },
      },
    });
  });

  test("marks mail as identity mismatch on registry hard error", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({ messages: [await signedInboxMail("msg-hard-error")] }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = {
      normalizeTrust: vi.fn(async () => ({ status: "identity_mismatch", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchEvent(
      mcp as never,
      client as never,
      pinStore,
      trust,
      self,
      new Set(),
      { type: "mail_message", message_id: "msg-hard-error" } satisfies AgentEvent,
    );

    expect(notification).toHaveBeenCalledWith({
      method: "notifications/claude/channel",
      params: {
        content: "world",
        meta: {
          type: "mail",
          from: "acme.com/alice",
          message_id: "msg-hard-error",
          subject: "hello",
          verified: "false",
        },
      },
    });
    expect(pinStore.pins.size).toBe(0);
  });

  test("renders mail verified when stable recipient binding matches the receiver", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [await signedInboxMailWithStableRecipient("msg-stable-recipient", self.stableID)],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: vi.fn(async () => ({ outcome: "OK_DEGRADED" })),
        resolveIdentity: vi.fn(async () => ({
          did: vectors.did,
          stableID: vectors.stableID,
          address: "acme.com/alice",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          lifetime: "persistent",
        })),
      } as never,
      "backend:acme.com",
      self.did,
      self.stableID,
    );

    await dispatchEvent(
      mcp as never,
      client as never,
      pinStore,
      trust,
      self,
      new Set(),
      { type: "mail_message", message_id: "msg-stable-recipient" } satisfies AgentEvent,
    );

    expect(notification).toHaveBeenCalledWith({
      method: "notifications/claude/channel",
      params: {
        content: "stable-bound mail",
        meta: {
          type: "mail",
          from: "acme.com/alice",
          message_id: "msg-stable-recipient",
          subject: "stable recipient",
          verified: "true",
        },
      },
    });
  });

  test("fetches mail by triggering message_id instead of a latest-10 window", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({ messages: [await signedInboxMail("msg-windowed")] }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = {
      normalizeTrust: vi.fn(async () => ({ status: "verified", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchEvent(
      mcp as never,
      client as never,
      pinStore,
      trust,
      self,
      new Set(),
      { type: "mail_message", message_id: "msg-windowed" } satisfies AgentEvent,
    );

    expect(client.get).toHaveBeenCalledWith(
      "/v1/messages/inbox?unread_only=true&limit=200&message_id=msg-windowed",
    );
    expect(notification).toHaveBeenCalledTimes(1);
  });

  test("fetches chat by triggering message_id instead of a latest-10 window", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [
          {
            message_id: "chat-msg-windowed",
            from_agent: "alice",
            from_address: "acme.com/alice",
            body: "hello",
            timestamp: "2025-01-01T00:00:00Z",
            sender_leaving: false,
            from_did: vectors.did,
            from_stable_id: vectors.stableID,
            verification_status: "verified",
          },
        ],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = {
      normalizeTrust: vi.fn(async () => ({ status: "verified", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchEvent(
      mcp as never,
      client as never,
      pinStore,
      trust,
      self,
      new Set(),
      { type: "chat_message", session_id: "sess-1", message_id: "chat-msg-windowed" } satisfies AgentEvent,
    );

    expect(client.get).toHaveBeenCalledWith(
      "/v1/chat/sessions/sess-1/messages?unread_only=true&limit=2000&message_id=chat-msg-windowed",
    );
    expect(notification).toHaveBeenCalledTimes(1);
  });

  test("skips self-authored mail by concrete address", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "msg-self-address",
          from_agent_id: "agent-self",
          from_alias: "",
          from_address: "acme.com/eve",
          subject: "note",
          body: "self",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
          verification_status: "verified",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = {
      normalizeTrust: vi.fn(async () => ({ status: "verified", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchEvent(
      mcp as never,
      client as never,
      pinStore,
      trust,
      self,
      new Set(),
      { type: "mail_message", message_id: "msg-self-address" } satisfies AgentEvent,
    );

    expect(notification).not.toHaveBeenCalled();
  });

  test("skips self-authored chat by stable identity when alias differs", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-msg-self-stable",
          from_agent: "someone-else",
          body: "self",
          timestamp: "2025-01-01T00:00:00Z",
          sender_leaving: false,
          from_did: "did:key:self-eve",
          from_stable_id: "did:aw:self-eve",
          verification_status: "verified",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = {
      normalizeTrust: vi.fn(async () => ({ status: "verified", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchEvent(
      mcp as never,
      client as never,
      pinStore,
      trust,
      self,
      new Set(),
      { type: "chat_message", session_id: "sess-1", message_id: "chat-msg-self-stable" } satisfies AgentEvent,
    );

    expect(notification).not.toHaveBeenCalled();
  });
});
