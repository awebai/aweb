import assert from "node:assert/strict";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  dispatchAgentEvent,
  PinStore,
  type AgentEvent,
  type ChannelAwakening,
  type SenderTrustManager,
} from "@awebai/channel-core";
import {
  createWakeDispatcher,
  deliveryOptionsForAwakening,
  type WakeLogEvent,
} from "../src/wake.ts";

function awakening(overrides: Partial<ChannelAwakening> = {}): ChannelAwakening {
  return {
    kind: "chat",
    content: "hello",
    deliveryIntent: "wake",
    meta: {
      type: "chat",
      from: "alice",
      message_id: "msg-1",
      conversation_id: "conv-1",
      session_id: "sess-1",
      sender_leaving: "true",
      trust_status: "verified",
      verified: "true",
    },
    ...overrides,
  };
}

function fakePi(sendMessage: ExtensionAPI["sendMessage"]): ExtensionAPI {
  return {
    sendMessage,
  } as ExtensionAPI;
}

function waitForDrain(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

test("idle chat wake triggers a new Pi turn", () => {
  assert.deepEqual(deliveryOptionsForAwakening(awakening(), false), {
    triggerTurn: true,
  });
});

test("active-turn chat wake queues as follow-up without nested triggerTurn", () => {
  assert.deepEqual(deliveryOptionsForAwakening(awakening(), true), {
    deliverAs: "followUp",
  });
});

test("active-turn waiting chat steers without nested triggerTurn", () => {
  assert.deepEqual(deliveryOptionsForAwakening(awakening({
    deliveryIntent: "steer",
    meta: {
      ...awakening().meta,
      sender_waiting: "true",
    },
  }), true), {
    deliverAs: "steer",
  });
});

test("idle waiting chat steers and triggers a turn", () => {
  assert.deepEqual(deliveryOptionsForAwakening(awakening({
    deliveryIntent: "steer",
    meta: {
      ...awakening().meta,
      sender_waiting: "true",
    },
  }), false), {
    deliverAs: "steer",
    triggerTurn: true,
  });
});

test("ambient events are next-turn only", () => {
  assert.deepEqual(deliveryOptionsForAwakening(awakening({ deliveryIntent: "ambient" }), false), {
    deliverAs: "nextTurn",
  });
  assert.deepEqual(deliveryOptionsForAwakening(awakening({ deliveryIntent: "ambient" }), true), {
    deliverAs: "nextTurn",
  });
});

test("active-turn wake stays pending until turn end, then resolves after Pi accepts it", async () => {
  const calls: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  const dispatcher = createWakeDispatcher(fakePi((message, options) => {
    calls.push([message, options]);
  }), () => {});

  dispatcher.setTurnActive(true);
  let settled = false;
  const delivered = dispatcher.enqueue(awakening()).then(() => { settled = true; });
  await waitForDrain();

  assert.equal(calls.length, 0);
  assert.equal(settled, false);

  dispatcher.setTurnActive(false);
  await delivered;

  assert.equal(calls.length, 1);
  assert.equal(calls[0][0].customType, "aweb-channel");
  assert.deepEqual(calls[0][1], { triggerTurn: true });
  assert.equal(settled, true);
});

test("mid-turn mail stays unread until turn-end injection succeeds", async () => {
  const sends: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  const dispatcher = createWakeDispatcher(fakePi((message, options) => {
    sends.push([message, options]);
  }), () => {});
  dispatcher.setTurnActive(true);
  const posts: string[] = [];
  const client = {
    get: async () => ({
      messages: [{
        message_id: "mail-mid-turn",
        from_agent_id: "agent-alice",
        from_alias: "alice",
        from_address: "acme.com/alice",
        to_alias: "eve",
        subject: "hello",
        body: "deliver at turn end",
        priority: "normal",
        created_at: "2026-07-23T00:00:00Z",
      }],
    }),
    post: async (path: string) => { posts.push(path); },
  };
  const trust = {
    normalizeTrust: async () => ({ status: "verified", stored: false }),
  } as unknown as SenderTrustManager;

  const dispatch = dispatchAgentEvent(
    {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self: { alias: "eve", address: "acme.com/eve", did: "did:key:eve", stableID: "" },
      onAwakening: (event) => dispatcher.enqueue(event),
    },
    new Set(),
    { type: "mail_message", message_id: "mail-mid-turn" } satisfies AgentEvent,
  );
  await waitForDrain();

  assert.equal(sends.length, 0);
  assert.deepEqual(posts, []);

  dispatcher.setTurnActive(false);
  await dispatch;

  assert.equal(sends.length, 1);
  assert.deepEqual(posts, ["/v1/messages/mail-mid-turn/ack"]);
});

test("dispatcher rejects a pending active-turn wake when the session shuts down", async () => {
  const dispatcher = createWakeDispatcher(fakePi(() => {
    assert.fail("pending wake must not inject after shutdown");
  }), () => {});
  dispatcher.setTurnActive(true);
  const delivered = dispatcher.enqueue(awakening());

  dispatcher.close(new Error("session shutdown"));

  await assert.rejects(delivered, /session shutdown/);
});

test("in-flight shutdown rejection prevents source acknowledgment after late send settlement", async () => {
  let settleSend: (() => void) | undefined;
  let markStarted: (() => void) | undefined;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  const dispatcher = createWakeDispatcher(fakePi(() => {
    markStarted?.();
    return new Promise<void>((resolve) => { settleSend = resolve; });
  }), () => {});
  const posts: string[] = [];
  const client = {
    get: async () => ({
      messages: [{
        message_id: "mail-in-flight-shutdown",
        from_agent_id: "agent-alice",
        from_alias: "alice",
        from_address: "acme.com/alice",
        to_alias: "eve",
        subject: "hello",
        body: "do not ack after shutdown",
        priority: "normal",
        created_at: "2026-07-23T00:00:00Z",
      }],
    }),
    post: async (path: string) => { posts.push(path); },
  };
  const trust = {
    normalizeTrust: async () => ({ status: "verified", stored: false }),
  } as unknown as SenderTrustManager;
  const dispatch = dispatchAgentEvent(
    {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self: { alias: "eve", address: "acme.com/eve", did: "did:key:eve", stableID: "" },
      onAwakening: (event) => dispatcher.enqueue(event),
    },
    new Set(),
    { type: "mail_message", message_id: "mail-in-flight-shutdown" } satisfies AgentEvent,
  );
  await started;

  dispatcher.close(new Error("session shutdown"));
  await assert.rejects(dispatch, /session shutdown/);
  assert.deepEqual(posts, []);

  settleSend?.();
  await waitForDrain();
  assert.deepEqual(posts, []);
});

test("dispatcher serializes delivery and rejects on sendMessage failures", async () => {
  const calls: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  const logs: Array<{ event: WakeLogEvent; fields?: Record<string, unknown> }> = [];
  const dispatcher = createWakeDispatcher(fakePi((message, options) => {
    calls.push([message, options]);
    throw new Error("pi rejected custom message");
  }), (event, fields) => logs.push({ event, fields }));

  const delivered = dispatcher.enqueue(awakening());
  await assert.rejects(delivered, /pi rejected custom message/);

  assert.equal(calls.length, 1);
  assert.equal(calls[0][0].customType, "aweb-channel");
  assert.deepEqual(calls[0][1], { triggerTurn: true });
  assert.equal(logs.some((entry) => entry.event === "wake_delivery_failed"), true);
  assert.equal(logs.some((entry) => entry.fields?.message === "pi rejected custom message"), true);
});

test("dispatcher awaits async sendMessage rejection without relying on global unhandledRejection", async () => {
  const logs: Array<{ event: WakeLogEvent; fields?: Record<string, unknown> }> = [];
  const dispatcher = createWakeDispatcher(fakePi((async () => {
    throw new Error("async pi rejection");
  }) as ExtensionAPI["sendMessage"]), (event, fields) => logs.push({ event, fields }));

  await assert.rejects(dispatcher.enqueue(awakening()), /async pi rejection/);

  assert.equal(logs.some((entry) => entry.event === "wake_delivery_failed"), true);
  assert.equal(logs.some((entry) => entry.fields?.message === "async pi rejection"), true);
  assert.equal(logs.some((entry) => entry.event === "wake_delivered"), false);
});
