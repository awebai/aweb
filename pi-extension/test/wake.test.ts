import assert from "node:assert/strict";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  dispatchAgentEvent,
  eventStreamRefusedAwakening,
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

test("a refused stream is shown in the status and logged once on entry and once on exit, not Pi model input", () => {
  const calls: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  const logs: string[] = [];
  const statuses: string[] = [];
  fakePi((message, options) => {
    calls.push([message, options]);
  });
  const ctx = {
    hasUI: true,
    ui: {
      theme: { fg: (_kind: string, text: string) => text },
      setStatus: (_key: string, value: string) => statuses.push(value),
    },
  };
  const nextAttemptAt = new Date(2026, 2, 1, 9, 5).getTime();

  handlePiStreamState({ state: "refused", cause: "401", retryInMs: 60_000, nextAttemptAt }, ctx, (message) => logs.push(message));
  handlePiStreamState({ state: "reconnected", endedRefusal: "401" }, ctx, (message) => logs.push(message));

  assert.equal(calls.length, 0);
  assert.deepEqual(logs, [
    "aweb: event stream refused: 401, next try 09:05",
    "aweb: event stream accepted again (was refused: 401)",
  ]);
  assert.deepEqual(statuses, ["✕ aweb events refused (401); next try 09:05", "✓ aweb connected"]);
});

test("the start of a refusal episode is the one stream state presented to Pi, as a notice from the channel itself", async () => {
  const calls: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  const logs: string[] = [];
  const pi = fakePi((message, options) => {
    calls.push([message, options]);
  });
  const ctx = { hasUI: false };
  const nextAttemptAt = new Date(2026, 2, 1, 9, 5).getTime();
  const refused = { state: "refused" as const, cause: "401", retryInMs: 60_000, nextAttemptAt, startsEpisode: true as const };

  // The stream state handler is the operator surface: it logs and presents nothing.
  handlePiStreamState(refused, ctx, (message) => logs.push(message));
  handlePiStreamState({ state: "reconnected", endedRefusal: "401" }, ctx, (message) => logs.push(message));
  assert.equal(logs.length, 2);
  assert.equal(calls.length, 0);

  // The channel loop presents the notice through the extension's awakening path.
  const dispatcher = createWakeDispatcher(pi, () => {});
  await createPiAwakeningHandler(dispatcher)(eventStreamRefusedAwakening(refused));
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0].customType, "aweb-channel");
  assert.equal(calls[0][0].content, [
    "aweb channel notice, from the aweb channel itself and not from another agent.",
    "",
    "The aweb server refused this channel's event stream (401). Mail and chat will not arrive until the stream is accepted again. The next attempt is at 09:05.",
  ].join("\n"));
  assert.deepEqual(calls[0][1], { triggerTurn: true });
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
