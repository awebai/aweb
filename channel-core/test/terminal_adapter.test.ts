import { describe, expect, test, vi } from "vitest";
import {
  createTerminalAwakeningHandler,
  normalizeTerminalReadiness,
  terminalReadyForIntent,
  type ChannelAwakening,
  type TerminalSession,
} from "../src/index.js";

function awakening(overrides: Partial<ChannelAwakening> = {}): ChannelAwakening {
  return {
    kind: "chat",
    content: "hello",
    deliveryIntent: "wake",
    meta: { type: "chat", message_id: "m1", session_id: "s1", from: "alice" },
    ...overrides,
  };
}

async function flush(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("terminal channel adapter", () => {
  test("normalizes readiness without treating unknown as fatal", () => {
    expect(normalizeTerminalReadiness("done", true)).toBe("idle");
    expect(normalizeTerminalReadiness("working", true)).toBe("working");
    expect(normalizeTerminalReadiness("surprise", true)).toBe("unknown");
    expect(normalizeTerminalReadiness("idle", false)).toBe("not-launched");
    expect(terminalReadyForIntent("unknown", "wake")).toBe(true);
    expect(terminalReadyForIntent("unknown", "steer")).toBe(true);
    expect(terminalReadyForIntent("unknown", "ambient")).toBe(false);
    expect(terminalReadyForIntent("working", "wake")).toBe(false);
  });

  test("ambient awakenings wait for a real wake before terminal input resolves", async () => {
    vi.useFakeTimers();
    try {
      const inputs: string[] = [];
      const session: TerminalSession = {
        inspect: vi.fn(async () => ({ present: true, state: "idle" })),
        input: vi.fn(async (_home, text) => { inputs.push(text); }),
      };
      const handler = createTerminalAwakeningHandler({ home: "/agent", session, retryDelayMs: 5 });
      let ambientResolved = false;
      const ambient = handler(awakening({ kind: "work", content: "task", deliveryIntent: "ambient", meta: { type: "work", task_id: "t1" } }))
        .then(() => { ambientResolved = true; });
      await vi.runOnlyPendingTimersAsync();
      await flush();
      expect(session.input).not.toHaveBeenCalled();
      expect(ambientResolved).toBe(false);

      const wake = handler(awakening({ content: "wake body" }));
      await vi.runOnlyPendingTimersAsync();
      await Promise.all([ambient, wake]);
      expect(session.input).toHaveBeenCalledTimes(1);
      expect(inputs[0]).toContain("task_id: t1");
      expect(inputs[0]).toContain("wake body");
    } finally {
      vi.useRealTimers();
    }
  });

  test("failed input stays queued and retries before channel-core delivery can resolve", async () => {
    vi.useFakeTimers();
    try {
      let attempts = 0;
      const session: TerminalSession = {
        inspect: vi.fn(async () => ({ present: true, state: "idle" })),
        input: vi.fn(async () => {
          attempts += 1;
          if (attempts === 1) throw new Error("backend refused input");
        }),
      };
      const handler = createTerminalAwakeningHandler({ home: "/agent", session, retryDelayMs: 5 });
      let resolved = false;
      const delivered = handler(awakening()).then(() => { resolved = true; });

      await vi.runOnlyPendingTimersAsync();
      await flush();
      expect(resolved).toBe(false);
      expect(session.input).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(5);
      await delivered;
      expect(resolved).toBe(true);
      expect(session.input).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  test("known-busy terminals defer without resolving until a later ready inspect", async () => {
    vi.useFakeTimers();
    try {
      const states = ["working", "idle"];
      const session: TerminalSession = {
        inspect: vi.fn(async () => ({ present: true, state: states.shift() || "idle" })),
        input: vi.fn(async () => {}),
      };
      const handler = createTerminalAwakeningHandler({ home: "/agent", session, retryDelayMs: 5 });
      let resolved = false;
      const delivered = handler(awakening()).then(() => { resolved = true; });

      await vi.runOnlyPendingTimersAsync();
      await flush();
      expect(resolved).toBe(false);
      expect(session.input).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(5);
      await delivered;
      expect(resolved).toBe(true);
      expect(session.input).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
