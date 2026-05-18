import { describe, expect, test, vi } from "vitest";
import {
  dispatchAgentEvent,
  PinStore,
  type AgentEvent,
  type ChannelAwakening,
  type SenderTrustManager,
} from "../../channel-core/src/index.js";

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

  test("does not ack mail when channel delivery succeeds", async () => {
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
    expect(client.post).not.toHaveBeenCalled();
  });

  test("does not mark chat read when channel delivery succeeds", async () => {
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
    expect(client.post).not.toHaveBeenCalled();
  });
});
