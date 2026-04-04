import { describe, expect, test, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AgentEvent } from "../src/api/events.js";
import { PinStore } from "../src/identity/pinstore.js";
import { signMessage, type MessageEnvelope } from "../src/identity/signing.js";
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

describe("dispatchEvent", () => {
  test("notifies claim_update events", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };

    await dispatchEvent(
      mcp as never,
      {} as never,
      new PinStore(),
      { normalizeTrust: vi.fn() } as unknown as SenderTrustManager,
      "eve",
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
      "eve",
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

  test("falls back to TOFU when registry verification is degraded", async () => {
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
      "eve",
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
      "eve",
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
});
