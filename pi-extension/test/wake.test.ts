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
import { createPiAwakeningHandler, handlePiStreamState } from "../src/index.ts";

test("transport reconnect and disconnect are diagnostics, not Pi model input", async () => {
  const calls: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  const logs: string[] = [];
  const statuses: string[] = [];
  const pi = fakePi((message, options) => {
    calls.push([message, options]);
  });
  const ctx = {
    hasUI: true,
    ui: {
      theme: { fg: (_kind: string, text: string) => text },
      setStatus: (_key: string, value: string) => statuses.push(value),
    },
  };

  handlePiStreamState({ state: "disconnected", cause: "network unavailable", retryInMs: 1000 }, ctx, (message) => logs.push(message));
  handlePiStreamState({ state: "reconnected" }, ctx, (message) => logs.push(message));
  handlePiStreamState({ state: "disconnected", cause: "connection closed", retryInMs: 2000 }, ctx, (message) => logs.push(message));

  assert.equal(calls.length, 0);
  assert.equal(logs.length, 3);
  assert.equal(statuses.length, 3);

  const dispatcher = createWakeDispatcher(pi, () => {});
  await createPiAwakeningHandler(dispatcher)(awakening());
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0].customType, "aweb-channel");
});

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

test("active-turn wake submits a follow-up and resolves after Pi accepts it", async () => {
  const calls: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  const dispatcher = createWakeDispatcher(fakePi((message, options) => {
    calls.push([message, options]);
  }), () => {});

  dispatcher.setTurnActive(true);
  let settled = false;
  const delivered = dispatcher.enqueue(awakening()).then(() => { settled = true; });
  await waitForDrain();

  try {
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0].customType, "aweb-channel");
    assert.deepEqual(calls[0][1], { deliverAs: "followUp" });
    assert.equal(settled, true);
  } finally {
    dispatcher.setTurnActive(false);
    await delivered;
  }
});

test("mid-turn mail is acknowledged only after Pi accepts the follow-up", async () => {
  const sends: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  let acceptSend: () => void = () => {};
  const accepted = new Promise<void>((resolve) => { acceptSend = resolve; });
  const dispatcher = createWakeDispatcher(fakePi((message, options) => {
    sends.push([message, options]);
    return accepted;
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
    normalizeResolvedTrust: async () => ({ status: "verified", stored: false }),
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
  for (let attempt = 0; attempt < 10 && sends.length === 0; attempt += 1) {
    await waitForDrain();
  }

  try {
    assert.equal(sends.length, 1);
    assert.deepEqual(sends[0][1], { deliverAs: "followUp" });
    assert.deepEqual(posts, []);
    acceptSend();
    await dispatch;
    assert.deepEqual(posts, ["/v1/messages/mail-mid-turn/ack"]);
  } finally {
    dispatcher.setTurnActive(false);
    acceptSend();
    await dispatch;
  }
});

test("dispatcher rejects a queued wake when the session shuts down", async () => {
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
    normalizeResolvedTrust: async () => ({ status: "verified", stored: false }),
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

for (const mode of [undefined, "line"] as const) {
  for (const kind of ["mail", "chat"] as const) {
    test(`${kind} ${mode ?? "default"} presentation keeps the acceptance/read boundary`, async (t) => {
      const previous = process.env.AWEB_WAKE_PRESENTATION;
      if (mode === undefined) delete process.env.AWEB_WAKE_PRESENTATION;
      else process.env.AWEB_WAKE_PRESENTATION = mode;
      t.after(() => {
        if (previous === undefined) delete process.env.AWEB_WAKE_PRESENTATION;
        else process.env.AWEB_WAKE_PRESENTATION = previous;
      });
      const id = "12345678-1234-1234-1234-123456789abc";
      const session = "87654321-4321-4321-4321-cba987654321";
      const sends: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
      let accept!: () => void;
      const accepted = new Promise<void>((resolve) => { accept = resolve; });
      const dispatcher = createWakeDispatcher(fakePi((message, options) => {
        sends.push([message, options]);
        return accepted;
      }), () => {});
      const posts: Array<[string, unknown]> = [];
      const client = {
        get: async () => ({ messages: [{ message_id: id, from_alias: "alice", from_agent: "alice", subject: "hello", body: "private body", created_at: "2026-01-01T00:00:00Z", timestamp: "2026-01-01T00:00:00Z" }] }),
        post: async (path: string, body?: unknown) => { posts.push([path, body]); },
      };
      const pending = dispatchAgentEvent({
        client: client as never, pinStore: new PinStore(),
        trust: { normalizeResolvedTrust: async () => ({ status: "verified", stored: false }) } as unknown as SenderTrustManager,
        self: { alias: "eve", address: "", did: "did:key:eve", stableID: "" },
        onAwakening: (event) => dispatcher.enqueue(event),
      }, new Set(), { type: kind === "mail" ? "mail_message" : "chat_message", message_id: id, session_id: session });
      try {
        for (let attempt = 0; attempt < 20 && sends.length === 0; attempt += 1) await waitForDrain();
        assert.equal(sends.length, 1);
        const content = sends[0][0].content;
        if (mode === "line") {
          assert.equal(content, kind === "mail"
            ? `aweb mail waiting: "hello" from alice — read: aw mail show --message-id ${id}; reply: aw mail reply ${id}`
            : `aweb chat waiting: from alice — read: aw chat history --session-id ${session} --message-id ${id}; reply: aw chat send --session-id ${session}`);
        } else {
          assert.ok(typeof content === "string" && content.includes("private body") && content.includes(`aweb ${kind} event received.`));
        }
        assert.deepEqual(posts, []);
      } finally { accept(); await pending; dispatcher.close(); }
      assert.deepEqual(posts, kind === "mail" ? [[`/v1/messages/${id}/ack`, undefined]] : [[`/v1/chat/sessions/${session}/read`, { message_ids: [id] }]]);
    });
  }
}
