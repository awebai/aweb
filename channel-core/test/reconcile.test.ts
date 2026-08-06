import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

import { APIClient } from "../src/api/client.js";
import type { AgentEvent } from "../src/api/events.js";
import {
  DeliveryStore,
  dispatchAgentEvent,
  startChannelLoop,
  type ChannelAwakening,
} from "../src/channel.js";
import { PinStore } from "../src/identity/pinstore.js";
import type { SenderTrustManager } from "../src/identity/trust.js";
import {
  AgentEventScheduler,
  RECONCILE_INTERVAL_MS,
  reconcileDurableState,
  runDurableReconcile,
  type ReconcileEventSink,
} from "../src/reconcile.js";

function snapshotClient(get: (path: string, signal?: AbortSignal) => Promise<unknown>): APIClient {
  return { get: vi.fn(get) } as unknown as APIClient;
}

function recordingSink(events: AgentEvent[]): ReconcileEventSink {
  return {
    enqueue: vi.fn(async (event: AgentEvent) => { events.push(event); }),
  };
}

const self = {
  alias: "eve",
  address: "acme.com/eve",
  did: "did:key:self-eve",
  stableID: "did:aw:self-eve",
};
const trust = {
  normalizeTrust: vi.fn(async () => ({ status: "verified", stored: false })),
} as unknown as SenderTrustManager;

function inboxMessage(messageID: string) {
  return {
    message_id: messageID,
    conversation_id: "conversation-durable",
    from_agent_id: "agent-1",
    from_alias: "alice",
    from_address: "acme.com/alice",
    to_alias: "eve",
    subject: "delivery",
    body: "durable mail",
    priority: "normal",
    created_at: "2026-08-06T00:00:00Z",
  };
}

function chatMessage(messageID: string) {
  return {
    message_id: messageID,
    conversation_id: "session-durable",
    from_agent: "alice",
    from_address: "acme.com/alice",
    body: "durable chat",
    timestamp: "2026-08-06T00:00:00Z",
    sender_leaving: false,
  };
}

function dispatchClient(messages: ReturnType<typeof inboxMessage>[]) {
  return {
    get: vi.fn(async () => ({ messages })),
    post: vi.fn(async () => undefined),
    openSSE: vi.fn(),
  };
}

function dispatchOptions(
  client: ReturnType<typeof dispatchClient>,
  deliveryStore: DeliveryStore,
  awakenings: ChannelAwakening[],
) {
  return {
    client: client as never,
    pinStore: new PinStore(),
    trust,
    self,
    deliveryStore,
    onAwakening: (awakening: ChannelAwakening) => { awakenings.push(awakening); },
  };
}

describe("durable communication reconcile", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  test("serializes one mail lane and each chat lane without blocking other events", async () => {
    let releaseMail: (() => void) | undefined;
    let releaseChat: (() => void) | undefined;
    const started: string[] = [];
    const scheduler = new AgentEventScheduler(async (event) => {
      const id = event.message_id || event.signal_id || "";
      started.push(id);
      if (id === "mail-1") {
        await new Promise<void>((resolve) => { releaseMail = resolve; });
      }
      if (id === "chat-1") {
        await new Promise<void>((resolve) => { releaseChat = resolve; });
      }
    });

    const jobs = [
      scheduler.enqueue({ type: "mail_message", message_id: "mail-1" }),
      scheduler.enqueue({ type: "mail_message", message_id: "mail-2" }),
      scheduler.enqueue({ type: "chat_message", session_id: "session-a", message_id: "chat-1" }),
      scheduler.enqueue({ type: "chat_message", session_id: "session-a", message_id: "chat-2" }),
      scheduler.enqueue({ type: "control_interrupt", signal_id: "control-1" }),
    ];
    await Promise.resolve();
    await Promise.resolve();

    expect(started).toEqual(expect.arrayContaining(["mail-1", "chat-1", "control-1"]));
    expect(started).not.toContain("mail-2");
    expect(started).not.toContain("chat-2");

    releaseMail?.();
    releaseChat?.();
    await Promise.all(jobs);
    await scheduler.drain();
    expect(started.indexOf("mail-2")).toBeGreaterThan(started.indexOf("mail-1"));
    expect(started.indexOf("chat-2")).toBeGreaterThan(started.indexOf("chat-1"));
  });

  test("simultaneous stream and sweep mail discovery notifies and marks once", async () => {
    const deliveryStore = await DeliveryStore.load(
      join(await mkdtemp(join(tmpdir(), "aweb-reconcile-race-")), "delivered.json"),
    );
    const message = inboxMessage("mail-race");
    const client = dispatchClient([message]);
    const awakenings: ChannelAwakening[] = [];
    const dispatched = new Set<string>();
    const scheduler = new AgentEventScheduler((event) => dispatchAgentEvent(
      dispatchOptions(client, deliveryStore, awakenings),
      dispatched,
      event,
    ));

    await Promise.all([
      scheduler.enqueue({ type: "mail_message", message_id: message.message_id }),
      scheduler.enqueue({ type: "mail_message", message_id: message.message_id }),
    ]);

    expect(awakenings).toHaveLength(1);
    expect(deliveryStore.has(`mail:${message.conversation_id}:${message.message_id}`)).toBe(true);
    expect(client.post).toHaveBeenCalledTimes(1);
  });

  test("ack failure after durable mark retries without another notification", async () => {
    const deliveryStore = await DeliveryStore.load(
      join(await mkdtemp(join(tmpdir(), "aweb-reconcile-ack-")), "delivered.json"),
    );
    const message = inboxMessage("mail-ack-retry");
    const client = dispatchClient([message]);
    client.post.mockRejectedValueOnce(new Error("ack unavailable"));
    const awakenings: ChannelAwakening[] = [];
    const dispatched = new Set<string>();
    const scheduler = new AgentEventScheduler(
      (event) => dispatchAgentEvent(
        dispatchOptions(client, deliveryStore, awakenings),
        dispatched,
        event,
      ),
      vi.fn(),
    );

    await scheduler.enqueue({ type: "mail_message", message_id: message.message_id });
    await scheduler.enqueue({ type: "mail_message", message_id: message.message_id });
    expect(deliveryStore.has(`mail:${message.conversation_id}:${message.message_id}`)).toBe(true);
    expect(awakenings).toHaveLength(1);

    await scheduler.enqueue({ type: "mail_message", message_id: message.message_id });
    expect(awakenings).toHaveLength(1);
    expect(client.post).toHaveBeenCalledTimes(2);
  });

  test("heartbeat-only stream reconciles pending mail and chat within the interval", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const deliveryStore = await DeliveryStore.load(
      join(await mkdtemp(join(tmpdir(), "aweb-reconcile-loop-")), "delivered.json"),
    );
    const mail = inboxMessage("mail-durable");
    const chat = chatMessage("chat-durable");
    const encoder = new TextEncoder();
    const client = dispatchClient([mail]);
    client.get.mockImplementation(async (path: string) => {
      if (path.startsWith("/v1/messages/inbox?")) return { messages: [mail] };
      if (path === "/v1/chat/pending") {
        return { pending: [{ session_id: "session-durable", unread_count: 1 }] };
      }
      if (path.startsWith("/v1/chat/sessions/session-durable/messages?")) {
        return { messages: [chat] };
      }
      throw new Error(`unexpected path ${path}`);
    });
    client.openSSE.mockImplementation(async (_path: string, signal?: AbortSignal) => {
      const body = new ReadableStream<Uint8Array>({
        start(stream) {
          stream.enqueue(encoder.encode(": heartbeat\n\n"));
          signal?.addEventListener("abort", () => {
            try { stream.close(); } catch { /* already closed */ }
          }, { once: true });
        },
      });
      return new Response(body, { headers: { "content-type": "text/event-stream" } });
    });
    const awakenings: ChannelAwakening[] = [];
    const running = startChannelLoop({
      ...dispatchOptions(client, deliveryStore, awakenings),
      signal: controller.signal,
      teamID: "backend:acme.com",
      reconcileSchedule: { intervalMs: 100, jitterRatio: 0 },
      onAwakening: (awakening) => {
        awakenings.push(awakening);
        if (new Set(awakenings.map((item) => item.kind)).size === 2) controller.abort();
      },
    });

    await vi.advanceTimersByTimeAsync(100);
    await running;

    expect(awakenings.map((item) => item.kind)).toEqual(expect.arrayContaining(["mail", "chat"]));
    expect(awakenings.filter((item) => item.kind === "mail")).toHaveLength(1);
    expect(awakenings.filter((item) => item.kind === "chat")).toHaveLength(1);
    expect(client.openSSE).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  test("fetches mail and chat independently and drains bounded backlog passes", async () => {
    const mailPages = [
      Array.from({ length: 200 }, (_, index) => ({ message_id: `mail-${index}` })),
      [{ message_id: "mail-200" }],
    ];
    const firstChatPage = Array.from({ length: 51 }, (_, index) => ({
      session_id: `session-${index}`,
      conversation_id: `session-${index}`,
      unread_count: index === 0 ? 2000 : 1,
      sender_waiting: index === 0,
    }));
    const chatPages = [firstChatPage, [firstChatPage[50]]];
    const client = snapshotClient(async (path) => {
      if (path.startsWith("/v1/messages/inbox?")) {
        return { messages: mailPages.shift() || [] };
      }
      if (path === "/v1/chat/pending") {
        return { pending: chatPages.shift() || [] };
      }
      throw new Error(`unexpected path ${path}`);
    });
    const events: AgentEvent[] = [];
    const log = vi.fn();

    await reconcileDurableState(
      client,
      recordingSink(events),
      new AbortController().signal,
      log,
    );

    expect(events.filter((event) => event.type === "mail_message")).toHaveLength(2);
    const chatEvents = events.filter((event) => event.type === "chat_message");
    expect(chatEvents).toHaveLength(51);
    expect(new Set(chatEvents.map((event) => event.session_id)).size).toBe(51);
    expect(chatEvents[0]).toMatchObject({
      session_id: "session-0",
      sender_waiting: true,
    });
    expect(log).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledTimes(4);
  });

  test("delivers a healthy snapshot source even when its sibling fetch fails", async () => {
    const client = snapshotClient(async (path) => {
      if (path.startsWith("/v1/messages/inbox?")) throw new Error("mail unavailable");
      return {
        pending: [{
          session_id: "session-live",
          unread_count: 1,
          sender_waiting: false,
        }],
      };
    });
    const events: AgentEvent[] = [];

    await expect(reconcileDurableState(
      client,
      recordingSink(events),
      new AbortController().signal,
    )).rejects.toThrow("durable communication snapshot failed");

    expect(events).toEqual([expect.objectContaining({
      type: "chat_message",
      session_id: "session-live",
    })]);
  });

  test("a hung sweep cannot overlap and abort cancels its requests and timer", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const client = snapshotClient((_path, signal) => new Promise((_resolve, reject) => {
      signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
    }));
    const sink = recordingSink([]);

    const running = runDurableReconcile(
      client,
      sink,
      controller.signal,
      vi.fn(),
      { intervalMs: 100, maxBackoffMs: 800, jitterRatio: 0 },
    );
    await vi.advanceTimersByTimeAsync(100);
    expect(client.get).toHaveBeenCalledTimes(2);

    // A large time jump cannot start another run while both first-pass fetches
    // are unresolved. The stream's shared sink remains independently usable.
    await sink.enqueue({ type: "control_interrupt", signal_id: "still-live" });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(client.get).toHaveBeenCalledTimes(2);

    controller.abort(new Error("test shutdown"));
    await running;
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(client.get).toHaveBeenCalledTimes(2);
  });

  test("failed snapshots use bounded exponential backoff", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const client = snapshotClient(async () => { throw new Error("offline"); });
    const log = vi.fn();
    const running = runDurableReconcile(
      client,
      recordingSink([]),
      controller.signal,
      log,
      { intervalMs: 100, maxBackoffMs: 400, jitterRatio: 0 },
    );

    await vi.advanceTimersByTimeAsync(100);
    expect(client.get).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(199);
    expect(client.get).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(client.get).toHaveBeenCalledTimes(4);
    expect(log).toHaveBeenCalledWith(expect.stringContaining("bounded backoff"));

    controller.abort();
    await running;
    expect(vi.getTimerCount()).toBe(0);
  });

  test("the production interval remains below the stream deadline", () => {
    expect(RECONCILE_INTERVAL_MS).toBe(30_000);
    expect(RECONCILE_INTERVAL_MS).toBeLessThan(5 * 60_000);
  });
});

describe("APIClient reconcile cancellation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test("external abort cancels a JSON request before its 30-second timeout", async () => {
    const fetchMock = vi.fn<typeof fetch>((_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => {
        reject(new DOMException("aborted", "AbortError"));
      }, { once: true });
    }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new APIClient("https://app.example", {
      did: "did:key:z6Mktest",
      stableID: "did:aw:test",
      signingKey: new Uint8Array(32).fill(1),
      teamID: "backend:acme.com",
      teamCertificateHeader: "cert-header",
    });
    const controller = new AbortController();

    const request = client.get("/v1/chat/pending", controller.signal);
    controller.abort();

    await expect(request).rejects.toMatchObject({ name: "AbortError" });
    const requestSignal = (fetchMock.mock.calls[0][1] as RequestInit).signal;
    expect(requestSignal).toBeInstanceOf(AbortSignal);
    expect(requestSignal?.aborted).toBe(true);
  });
});
