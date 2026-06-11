import assert from "node:assert/strict";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { ChannelAwakening } from "@awebai/channel-core";
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

test("dispatcher serializes delivery and logs sendMessage failures", async () => {
  const calls: Array<Parameters<ExtensionAPI["sendMessage"]>> = [];
  const logs: Array<{ event: WakeLogEvent; fields?: Record<string, unknown> }> = [];
  const dispatcher = createWakeDispatcher(fakePi((message, options) => {
    calls.push([message, options]);
    throw new Error("pi rejected custom message");
  }), (event, fields) => logs.push({ event, fields }));

  dispatcher.setTurnActive(true);
  dispatcher.enqueue(awakening());
  await waitForDrain();

  assert.equal(calls.length, 1);
  assert.equal(calls[0][0].customType, "aweb-channel");
  assert.deepEqual(calls[0][1], { deliverAs: "followUp" });
  assert.equal(logs.some((entry) => entry.event === "wake_delivery_failed"), true);
  assert.equal(logs.some((entry) => entry.fields?.message === "pi rejected custom message"), true);
});

test("dispatcher awaits async sendMessage rejection without relying on global unhandledRejection", async () => {
  const logs: Array<{ event: WakeLogEvent; fields?: Record<string, unknown> }> = [];
  const dispatcher = createWakeDispatcher(fakePi((async () => {
    throw new Error("async pi rejection");
  }) as ExtensionAPI["sendMessage"]), (event, fields) => logs.push({ event, fields }));

  dispatcher.enqueue(awakening());
  await waitForDrain();

  assert.equal(logs.some((entry) => entry.event === "wake_delivery_failed"), true);
  assert.equal(logs.some((entry) => entry.fields?.message === "async pi rejection"), true);
  assert.equal(logs.some((entry) => entry.event === "wake_delivered"), false);
});
