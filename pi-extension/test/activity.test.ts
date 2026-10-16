// Pi's lifecycle events drive the session's activity emitter
// (docs/agent-activity.md, "Emitters"). An agent run (agent_start/agent_end)
// is the activity turn; Pi's turn_start/turn_end fire per model call.
import assert from "node:assert/strict";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerActivityHandlers, type ActivityTarget } from "../src/activity.js";

type Handler = (event: unknown, ctx?: unknown) => unknown;

function fakePi(): { pi: ExtensionAPI; emit: (name: string, event: unknown) => void } {
  const handlers = new Map<string, Handler[]>();
  const pi = {
    on: (name: string, handler: Handler) => {
      handlers.set(name, [...(handlers.get(name) ?? []), handler]);
    },
  } as unknown as ExtensionAPI;
  return { pi, emit: (name, event) => (handlers.get(name) ?? []).forEach(handler => handler(event)) };
}

function recorder(): { target: ActivityTarget; calls: unknown[][] } {
  const calls: unknown[][] = [];
  const target: ActivityTarget = {
    turnStarted: () => calls.push(["turnStarted"]),
    thinking: () => calls.push(["thinking"]),
    writing: () => calls.push(["writing"]),
    tool: (name, input) => calls.push(["tool", name, input]),
    turnEnded: () => calls.push(["turnEnded"]),
  };
  return { target, calls };
}

function update(type: string): unknown {
  return { type: "message_update", message: {}, assistantMessageEvent: { type } };
}

test("an agent run is one activity turn", () => {
  const { pi, emit } = fakePi();
  const { target, calls } = recorder();
  registerActivityHandlers(pi, () => target);

  emit("agent_start", { type: "agent_start" });
  emit("turn_start", { type: "turn_start", turnIndex: 0, timestamp: 0 });
  emit("turn_end", { type: "turn_end", turnIndex: 0 });
  emit("turn_start", { type: "turn_start", turnIndex: 1, timestamp: 0 });
  emit("agent_end", { type: "agent_end" });

  assert.deepEqual(calls, [["turnStarted"], ["turnEnded"]]);
});

test("reasoning, reply text and tools map to their phases", () => {
  const { pi, emit } = fakePi();
  const { target, calls } = recorder();
  registerActivityHandlers(pi, () => target);

  emit("message_update", update("thinking_start"));
  emit("message_update", update("thinking_delta"));
  emit("tool_execution_start", { type: "tool_execution_start", toolCallId: "c1", toolName: "bash", args: { command: "pytest" } });
  emit("tool_execution_end", { type: "tool_execution_end", toolCallId: "c1", toolName: "bash" });
  emit("message_update", update("text_start"));
  emit("message_update", update("text_delta"));
  emit("message_update", update("toolcall_start"));

  assert.deepEqual(calls, [
    ["thinking"],
    ["tool", "bash", { command: "pytest" }],
    ["thinking"],
    ["writing"],
  ]);
});

test("without a session emitter the handlers do nothing", () => {
  const { pi, emit } = fakePi();
  registerActivityHandlers(pi, () => undefined);

  assert.doesNotThrow(() => {
    emit("agent_start", { type: "agent_start" });
    emit("tool_execution_start", { type: "tool_execution_start", toolCallId: "c1", toolName: "bash", args: {} });
    emit("agent_end", { type: "agent_end" });
  });
});

test("the handlers follow the current session's emitter", () => {
  const { pi, emit } = fakePi();
  const first = recorder();
  const second = recorder();
  let current: ActivityTarget | undefined = first.target;
  registerActivityHandlers(pi, () => current);

  emit("agent_start", { type: "agent_start" });
  current = second.target;
  emit("agent_end", { type: "agent_end" });

  assert.deepEqual(first.calls, [["turnStarted"]]);
  assert.deepEqual(second.calls, [["turnEnded"]]);
});
