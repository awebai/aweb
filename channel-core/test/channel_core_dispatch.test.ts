import { describe, expect, test, vi } from "vitest";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  consumeAgentEvents,
  DeliveryStore,
  dispatchAgentEvent,
  formatAwakeningForAgent,
  PinStore,
  type AgentEvent,
  type ChannelAwakening,
  SenderTrustManager,
} from "../src/index.js";
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
  const acceptingPinStoreWriter = {
    compareAndSet: vi.fn(async () => {}),
  };

  test("pending mid-turn mail does not block control events from the SSE stream", async () => {
    let finishMail: (() => void) | undefined;
    const awakenings: ChannelAwakening[] = [];
    const onAwakening = vi.fn((awakening: ChannelAwakening) => {
      awakenings.push(awakening);
      if (awakening.kind === "mail") {
        return new Promise<void>((resolve) => { finishMail = resolve; });
      }
      return Promise.resolve();
    });
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-lane-1",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "mid-turn",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield { type: "mail_message", message_id: "mail-lane-1" };
      yield { type: "control_interrupt", signal_id: "interrupt-1" };
    }

    const consuming = consumeAgentEvents(
      { client: client as never, pinStore: new PinStore(), trust, self, onAwakening },
      new Set(),
      events(),
    );
    await vi.waitFor(() => expect(awakenings.some((item) => item.kind === "control")).toBe(true));

    expect(awakenings.some((item) => item.kind === "mail")).toBe(true);
    expect(client.post).not.toHaveBeenCalled();
    finishMail?.();
    await consuming;
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-lane-1/ack");
  });

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

  test("delivery-store lock failure rejects without creating an in-memory acknowledgment path", { timeout: 15_000 }, async () => {
    const storePath = join(await mkdtemp(join(tmpdir(), "aweb-channel-lock-fail-")), "delivered.json");
    const deliveryStore = await DeliveryStore.load(storePath);
    await mkdir(`${storePath}.lock`);
    const dispatched = new Set<string>();
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-lock-fail",
          conversation_id: "conv-lock-fail",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "must remain pending",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await expect(dispatchAgentEvent(
      { client: client as never, pinStore: new PinStore(), trust, self, deliveryStore, onAwakening },
      dispatched,
      { type: "mail_message", message_id: "mail-lock-fail" } satisfies AgentEvent,
    )).rejects.toMatchObject({ code: "ELOCKED" });

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(dispatched).toHaveLength(0);
    expect(deliveryStore.has("mail:conv-lock-fail:mail-lock-fail")).toBe(false);
    expect(client.post).not.toHaveBeenCalled();
  });

  test("event-loop logs name the quarantined store and leave upstream acknowledgment pending", async () => {
    const storePath = join(await mkdtemp(join(tmpdir(), "aweb-channel-corrupt-")), "delivered.json");
    const deliveryStore = await DeliveryStore.load(storePath);
    await writeFile(storePath, "{corrupt delivery state\n", "utf8");
    const onAwakening = vi.fn();
    const log = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-corrupt-store",
          conversation_id: "conv-corrupt-store",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "must remain pending",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield { type: "mail_message", message_id: "mail-corrupt-store" };
    }

    await consumeAgentEvents(
      { client: client as never, pinStore: new PinStore(), trust, self, deliveryStore, onAwakening },
      new Set(),
      events(),
      log,
    );

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/quarantined at .*\.corrupt-/i));
    expect(client.post).not.toHaveBeenCalled();
  });

  test("does not deliver or acknowledge a message when pin persistence fails", async () => {
    const onAwakening = vi.fn();
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-pin-failure",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "must not be delivered",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const storingTrust = {
      normalizeTrust: vi.fn()
        .mockResolvedValueOnce({ status: "verified", stored: true })
        .mockResolvedValueOnce({ status: "verified", stored: false }),
    } as unknown as SenderTrustManager;
    const pinStoreWriter = {
      compareAndSet: vi.fn(async () => { throw new Error("aw binary missing"); }),
    };

    await expect(dispatchAgentEvent(
      { client: client as never, pinStore, pinStoreWriter, trust: storingTrust, self, onAwakening },
      new Set(),
      { type: "mail_message", message_id: "mail-pin-failure" } satisfies AgentEvent,
    )).rejects.toThrow(/aw binary missing/);

    // The failed mutation remains undurable. Even if a retry's trust decision
    // makes no further change, it must retry persistence and stay closed.
    await expect(dispatchAgentEvent(
      { client: client as never, pinStore, pinStoreWriter, trust: storingTrust, self, onAwakening },
      new Set(),
      { type: "mail_message", message_id: "mail-pin-failure" } satisfies AgentEvent,
    )).rejects.toThrow(/aw binary missing/);

    expect(pinStoreWriter.compareAndSet).toHaveBeenCalledTimes(2);
    expect(onAwakening).not.toHaveBeenCalled();
    expect(client.post).not.toHaveBeenCalled();
  });

  test("skips and leaves unread only the inbox message whose verification throws", async () => {
    const poisonMessage = {
      message_id: "mail-poison",
      from_agent_id: "agent-1",
      from_alias: "alice",
      from_address: "acme.com/alice",
      to_alias: self.alias,
      to_address: self.address,
      subject: "poison",
      body: "malformed transport record",
      priority: "normal",
      created_at: "2025-01-01T00:00:00Z",
      get signed_payload(): string {
        throw new Error("unexpected per-message verification failure");
      },
    };
    const onAwakening = vi.fn();
    const log = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [poisonMessage, {
          message_id: "mail-good",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: self.alias,
          subject: "good",
          body: "still delivered",
          priority: "normal",
          created_at: "2025-01-01T00:00:01Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield { type: "mail_message", message_id: "mail-poison" };
    }

    await consumeAgentEvents(
      { client: client as never, pinStore: new PinStore(), trust, self, onAwakening },
      new Set(),
      events(),
      log,
    );

    expect(poisonMessage as Record<string, unknown>).toMatchObject({
      verification_status: "failed",
      verification_error: true,
    });
    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "still delivered",
    }));
    expect(client.post).not.toHaveBeenCalledWith("/v1/messages/mail-poison/ack");
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-good/ack");
    expect(log).toHaveBeenCalledWith(expect.stringContaining("mail-poison"));
    expect(log).toHaveBeenCalledWith(
      "aweb: skipped verification for 1 inbox message; it remains unread",
    );
  });

  test("keeps mail unread while host injection is pending", async () => {
    let finishDelivery: (() => void) | undefined;
    const onAwakening = vi.fn(() => new Promise<void>((resolve) => {
      finishDelivery = resolve;
    }));
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-pending-injection",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "wait for turn end",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    const dispatch = dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-pending-injection" } satisfies AgentEvent,
    );
    await vi.waitFor(() => expect(onAwakening).toHaveBeenCalledTimes(1));

    expect(client.post).not.toHaveBeenCalled();
    finishDelivery?.();
    await dispatch;
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-pending-injection/ack");
  });

  test("decrypts encrypted mail locally before channel delivery", async () => {
    const onAwakening = vi.fn();
    const localDecrypt = {
      mailMessage: vi.fn(async () => ({
        message_id: "mail-e2ee",
        subject: "decrypted subject",
        body: "decrypted mail body",
      })),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-e2ee",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "",
          body: "",
          priority: "normal",
          created_at: "2026-05-26T00:00:00Z",
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
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
        localDecrypt,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-e2ee" } satisfies AgentEvent,
    );

    expect(localDecrypt.mailMessage).toHaveBeenCalledWith("mail-e2ee");
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "decrypted mail body",
      meta: expect.objectContaining({ subject: "decrypted subject" }),
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-e2ee/ack");
  });

  test("does not ack encrypted mail when local decrypt fails", async () => {
    const onAwakening = vi.fn();
    const localDecrypt = {
      mailMessage: vi.fn(async () => {
        throw new Error("missing local encryption key");
      }),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-e2ee-fail",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "",
          body: "",
          priority: "normal",
          created_at: "2026-05-26T00:00:00Z",
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
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
        localDecrypt,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-e2ee-fail" } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "",
      meta: expect.objectContaining({
        encrypted: "true",
        decrypted: "false",
        decrypt_error: "missing local encryption key",
      }),
    }));
    expect(client.post).not.toHaveBeenCalled();
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

  test("decrypts encrypted chat locally before channel delivery", async () => {
    const onAwakening = vi.fn();
    const localDecrypt = {
      chatMessage: vi.fn(async () => ({
        message_id: "chat-e2ee",
        body: "decrypted chat body",
      })),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-e2ee",
          conversation_id: "sess-e2ee",
          from_agent: "alice",
          from_address: "acme.com/alice",
          body: "",
          timestamp: "2026-05-26T00:00:00Z",
          sender_leaving: false,
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
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
        localDecrypt,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: "sess-e2ee",
        conversation_id: "sess-e2ee",
        message_id: "chat-e2ee",
      } satisfies AgentEvent,
    );

    expect(localDecrypt.chatMessage).toHaveBeenCalledWith("sess-e2ee", "chat-e2ee");
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "decrypted chat body",
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/chat/sessions/sess-e2ee/read", { up_to_message_id: "chat-e2ee" });
  });

  test("does not mark encrypted chat read when local decrypt fails", async () => {
    const onAwakening = vi.fn();
    const localDecrypt = {
      chatMessage: vi.fn(async () => null),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-e2ee-fail",
          conversation_id: "sess-e2ee-fail",
          from_agent: "alice",
          from_address: "acme.com/alice",
          body: "",
          timestamp: "2026-05-26T00:00:00Z",
          sender_leaving: false,
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
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
        localDecrypt,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: "sess-e2ee-fail",
        conversation_id: "sess-e2ee-fail",
        message_id: "chat-e2ee-fail",
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "",
      meta: expect.objectContaining({
        encrypted: "true",
        decrypted: "false",
      }),
    }));
    expect(client.post).not.toHaveBeenCalled();
  });

  test("retries mail ack without re-delivering when previous ack failed after delivery", async () => {
    const onAwakening = vi.fn();
    const deliveryStore = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "aweb-channel-test-")), "delivered.json"));
    const dispatched = new Set<string>();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-retry",
          conversation_id: "conv-retry",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "deliver once",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn()
        .mockRejectedValueOnce(new Error("aweb: http 503"))
        .mockResolvedValueOnce(undefined),
    };
    const options = {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self,
      deliveryStore,
      onAwakening,
    };
    const event = { type: "mail_message", message_id: "mail-retry" } satisfies AgentEvent;

    await expect(dispatchAgentEvent(options, dispatched, event)).rejects.toThrow("503");
    await dispatchAgentEvent(options, dispatched, event);

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledTimes(2);
    expect(client.post).toHaveBeenNthCalledWith(1, "/v1/messages/mail-retry/ack");
    expect(client.post).toHaveBeenNthCalledWith(2, "/v1/messages/mail-retry/ack");
  });

  test("manual mail acknowledgment keeps unread reconnect replay deduplicated", async () => {
    const onAwakening = vi.fn();
    const deliveryStore = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "aweb-channel-test-")), "delivered.json"));
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-manual",
          conversation_id: "conv-manual",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "stay visible",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const options = {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self,
      deliveryStore,
      mailAcknowledgment: "manual" as const,
      onAwakening,
    };
    const event = { type: "mail_message", message_id: "mail-manual" } satisfies AgentEvent;

    await dispatchAgentEvent(options, new Set(), event);
    await dispatchAgentEvent(options, new Set(), event);

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(client.post).not.toHaveBeenCalled();
  });

  test("retries chat read receipt without re-delivering when previous read failed after delivery", async () => {
    const onAwakening = vi.fn();
    const deliveryStore = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "aweb-channel-test-")), "delivered.json"));
    const dispatched = new Set<string>();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-retry",
          conversation_id: "sess-retry",
          from_agent: "alice",
          from_address: "acme.com/alice",
          body: "deliver once",
          timestamp: "2025-01-01T00:00:00Z",
          sender_leaving: false,
        }],
      }),
      post: vi.fn()
        .mockRejectedValueOnce(new Error("aweb: http 503"))
        .mockResolvedValueOnce(undefined),
    };
    const options = {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self,
      deliveryStore,
      onAwakening,
    };
    const event = {
      type: "chat_message",
      session_id: "sess-retry",
      conversation_id: "sess-retry",
      message_id: "chat-retry",
    } satisfies AgentEvent;

    await expect(dispatchAgentEvent(options, dispatched, event)).rejects.toThrow("503");
    await dispatchAgentEvent(options, dispatched, event);

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledTimes(2);
    expect(client.post).toHaveBeenNthCalledWith(1, "/v1/chat/sessions/sess-retry/read", { up_to_message_id: "chat-retry" });
    expect(client.post).toHaveBeenNthCalledWith(2, "/v1/chat/sessions/sess-retry/read", { up_to_message_id: "chat-retry" });
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

  test("live mail reports stale verifier cache without claiming identity mismatch", async () => {
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-stale-verifier",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          from_did: vectors.did,
          from_stable_id: vectors.stableID,
          to_alias: "eve",
          subject: "hello",
          body: "fresh identity",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
          verification_status: "verified",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const staleTrust = {
      normalizeTrust: vi.fn(async () => ({ status: "verification_stale", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: staleTrust,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-stale-verifier" } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      meta: expect.objectContaining({
        trust_status: "verification_stale",
        verified: "false",
      }),
    }));
  });

  test("surfaces pin migration conflicts in metadata and operator presentation", async () => {
    const awakenings: ChannelAwakening[] = [];
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-pin-conflict",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "conflicting identity",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const conflictTrust = {
      normalizeTrust: vi.fn(async () => ({ status: "pin_conflict", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: conflictTrust,
        self,
        onAwakening: (awakening) => { awakenings.push(awakening); },
      },
      new Set(),
      { type: "mail_message", message_id: "mail-pin-conflict" } satisfies AgentEvent,
    );

    expect(awakenings[0].meta).toMatchObject({
      trust_status: "pin_conflict",
      verified: "false",
    });
    const rendered = formatAwakeningForAgent(awakenings[0]);
    expect(rendered).toContain("two pin records conflict");
    expect(rendered).toContain("migration was refused");
    expect(rendered).toContain("avoid discarding trust state");
  });

  test("formats stale verification as retryable rather than identity mismatch", () => {
    const rendered = formatAwakeningForAgent({
      kind: "mail",
      content: "hello",
      deliveryIntent: "wake",
      meta: {
        type: "mail",
        from: "acme.com/alice",
        message_id: "mail-stale",
        trust_status: "verification_stale",
        verified: "false",
      },
    });

    expect(rendered).toContain("sender signature verified");
    expect(rendered).toContain("not an identity-mismatch finding");
    expect(rendered).toContain("retry verification");
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

  test("chat live dispatch accepts legacy stored-route recipient did:aw when it is this receiver", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/ama",
      from_did: vectors.did,
      to: self.stableID,
      to_did: self.stableID,
      type: "chat",
      subject: "",
      body: "legacy stored-route recipient",
      timestamp: "2025-01-01T00:00:00Z",
      from_stable_id: vectors.stableID,
      message_id: "chat-legacy-stable-to-did",
      conversation_id: "sess-legacy-stable",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
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
          from_did: vectors.did,
          from_stable_id: vectors.stableID,
          to_did: self.stableID,
          signature,
          signing_key_id: vectors.did,
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = new SenderTrustManager(
      client as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_VERIFIED", currentDidKey: vectors.did }),
        resolveIdentity: async () => ({
          did: vectors.did,
          stableID: vectors.stableID,
          address: env.from,
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "default:aweb.ai",
      self.did,
      self.stableID,
    );

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        pinStoreWriter: acceptingPinStoreWriter,
        trust,
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
      content: "legacy stored-route recipient",
      meta: expect.objectContaining({
        trust_status: "verified",
        verified: "true",
      }),
    }));
  });

  test("chat live dispatch hydrates trust fields from signed_payload when top-level row has stable did:aw", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/ama",
      from_did: vectors.did,
      to: self.stableID,
      to_did: "",
      type: "chat",
      subject: "",
      body: "signed-payload authority",
      timestamp: "2025-01-01T00:00:00Z",
      from_stable_id: vectors.stableID,
      to_stable_id: self.stableID,
      message_id: "chat-signed-payload-authority",
      conversation_id: "sess-signed-payload-authority",
    };
    const signedPayload = canonicalJSON(env);
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: env.message_id,
          conversation_id: env.conversation_id,
          from_agent: "ama",
          from_address: env.from,
          to_address: "acme.com/eve",
          body: env.body,
          timestamp: env.timestamp,
          sender_leaving: false,
          from_did: vectors.stableID,
          from_stable_id: vectors.stableID,
          signature,
          signing_key_id: vectors.did,
          signed_payload: signedPayload,
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = new SenderTrustManager(
      client as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_VERIFIED", currentDidKey: vectors.did }),
        resolveIdentity: async () => ({
          did: vectors.did,
          stableID: vectors.stableID,
          address: env.from,
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "default:aweb.ai",
      self.did,
      self.stableID,
    );

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        pinStoreWriter: acceptingPinStoreWriter,
        trust,
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
      content: "signed-payload authority",
      meta: expect.objectContaining({
        trust_status: "verified",
        verified: "true",
      }),
    }));
  });

  test("persists a verified-head advance when the trust path makes no pin write", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/ama",
      from_did: vectors.did,
      from_stable_id: vectors.stableID,
      to: self.stableID,
      to_did: self.did,
      to_stable_id: self.stableID,
      type: "chat",
      subject: "",
      body: "checkpoint-only persistence",
      timestamp: "2025-01-01T00:00:00Z",
      message_id: "chat-checkpoint-only",
      conversation_id: "sess-checkpoint-only",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
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
          from_did: vectors.did,
          from_stable_id: vectors.stableID,
          to_did: self.did,
          to_stable_id: self.stableID,
          signature,
          signing_key_id: vectors.did,
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const entryHash = "a".repeat(64);
    const trust = new SenderTrustManager(
      client as never,
      {
        verifyStableIdentity: async () => ({
          outcome: "OK_VERIFIED",
          currentDidKey: vectors.did,
          verifiedHead: {
            seq: 2,
            entryHash,
            stateHash: "b".repeat(64),
            currentDidKey: vectors.did,
            fetchedAt: Date.now(),
          },
        }),
        resolveIdentity: async () => ({
          did: vectors.did,
          stableID: vectors.stableID,
          address: env.from,
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "default:aweb.ai",
      self.did,
      self.stableID,
    );

    // The sender's stable identity already has a pin, but the claimed address
    // remains pinned to somebody else. The trust path therefore returns an
    // identity mismatch without writing either pin; checkpoint advance is the
    // only reason dispatch may consider the store dirty.
    const pinStore = new PinStore();
    pinStore.storePin(vectors.stableID, "aweb.ai/original-ama", "", "");
    const senderPin = pinStore.pins.get(vectors.stableID)!;
    senderPin.stable_id = vectors.stableID;
    senderPin.did_key = vectors.did;
    const addressOwner = "did:aw:address-owner";
    pinStore.storePin(addressOwner, env.from, "", "");
    const ownerPin = pinStore.pins.get(addressOwner)!;
    ownerPin.stable_id = addressOwner;
    ownerPin.did_key = "did:key:address-owner";

    const pinStorePath = join(await mkdtemp(join(tmpdir(), "aw-checkpoint-only-")), "known_agents.yaml");
    const pinStoreWriter = {
      compareAndSet: async (path: string, _expectedYAML: string, desiredYAML: string) => {
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, desiredYAML, "utf-8");
      },
    };
    await dispatchAgentEvent(
      { client: client as never, pinStore, pinStorePath, pinStoreWriter, trust, self, onAwakening },
      new Set(),
      {
        type: "chat_message",
        session_id: env.conversation_id,
        conversation_id: env.conversation_id,
        message_id: env.message_id,
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      meta: expect.objectContaining({ trust_status: "identity_mismatch" }),
    }));
    const reloaded = PinStore.fromYAML(await readFile(pinStorePath, "utf-8"));
    expect(reloaded.pins.get(vectors.stableID)).toMatchObject({
      log_seq: 2,
      log_entry_hash: entryHash,
    });
    expect(reloaded.addresses.get(env.from)).toBe(addressOwner);
  });

  test("dispatches app events without hydration and de-dupes by event_id", async () => {
    const onAwakening = vi.fn();
    const deliveryStore = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "aw-app-event-")), "delivered.json"));
    const event = {
      type: "app_event",
      event_id: "event-1",
      app_id: "folio",
      app_event_type: "folio/doc.changed",
      resource_ref: "aaai-m22-proof-1781686412",
      delivery_intent: "wake",
      producer_delivery_intent: "ambient",
      payload: { version: 8, source: "api" },
    } satisfies AgentEvent;

    const options = {
      client: {} as never,
      pinStore: new PinStore(),
      trust,
      self,
      onAwakening,
      deliveryStore,
    };
    const dispatched = new Set<string>();

    await dispatchAgentEvent(options, dispatched, event);
    await dispatchAgentEvent(options, dispatched, event);

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "app",
      content: "folio/doc.changed — aaai-m22-proof-1781686412 — version=8, source=api",
      deliveryIntent: "wake",
      meta: expect.objectContaining({
        type: "folio/doc.changed",
        app_id: "folio",
        resource_ref: "aaai-m22-proof-1781686412",
        producer_delivery_intent: "ambient",
        payload: '{"version":8,"source":"api"}',
      }),
    }));
  });

  test("formats app event content without empty resource_ref", async () => {
    const onAwakening = vi.fn();
    await dispatchAgentEvent(
      {
        client: {} as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "app_event",
        event_id: "event-no-resource",
        app_id: "folio",
        app_event_type: "folio/doc.changed",
        resource_ref: "",
        delivery_intent: "wake",
        payload: { version: 8, source: "api" },
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "app",
      content: "folio/doc.changed — version=8, source=api",
    }));
  });

  test("formats app awakening for agent with sanitized summary", () => {
    const rendered = formatAwakeningForAgent({
      kind: "app",
      content: "folio/doc.changed — aaai proof — bad key=ok Injected:, source=api",
      deliveryIntent: "wake",
      meta: {
        type: "folio/doc.changed\nInjected:",
        app_event_type: "folio/doc.changed\nInjected:",
        event_id: "event-sanitized",
        resource_ref: "aaai\r\nproof",
        payload: '{"bad\\nkey":"ok\\nInjected:"}',
      },
    });

    expect(rendered).toContain("App event:\nfolio/doc.changed — aaai proof — bad key=ok Injected:, source=api");
    expect(rendered).not.toContain("folio/doc.changed\nInjected:");
    expect(rendered).not.toContain("aaai\r\nproof");
  });

  test("formats app event content as a sanitized single line", async () => {
    const onAwakening = vi.fn();
    await dispatchAgentEvent(
      {
        client: {} as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "app_event",
        event_id: "event-sanitized",
        app_id: "folio",
        app_event_type: "folio/doc.changed\nInjected:",
        resource_ref: "aaai\r\nproof",
        delivery_intent: "wake",
        payload: { "bad\nkey": "ok\nInjected:", source: "api" },
      } satisfies AgentEvent,
    );

    const awakening = onAwakening.mock.calls[0][0] as ChannelAwakening;
    expect(awakening.content).toBe("folio/doc.changed Injected: — aaai proof — bad key=ok Injected:, source=api");
    expect(awakening.content).not.toMatch(/[\r\n]/);
  });
});
