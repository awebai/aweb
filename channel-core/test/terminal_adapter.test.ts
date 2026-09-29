import { describe, expect, test, vi } from "vitest";
import {
  createTerminalAwakeningHandler,
  createTerminalDeliveryReadinessGate,
  normalizeTerminalReadiness,
  terminalReadyForIntent,
  TerminalInactiveError,
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
  test("normalizes readiness with shell as a known defer state", () => {
    expect(normalizeTerminalReadiness("done", true)).toBe("idle");
    expect(normalizeTerminalReadiness("working", true)).toBe("working");
    expect(normalizeTerminalReadiness("shell", true)).toBe("shell");
    expect(normalizeTerminalReadiness("surprise", true)).toBe("unknown");
    expect(normalizeTerminalReadiness("idle", false)).toBe("not-launched");
    expect(terminalReadyForIntent("unknown", "wake")).toBe(true);
    expect(terminalReadyForIntent("unknown", "steer")).toBe(true);
    expect(terminalReadyForIntent("unknown", "ambient")).toBe(false);
    expect(terminalReadyForIntent("shell", "wake")).toBe(false);
    expect(terminalReadyForIntent("working", "wake")).toBe(false);
  });

  test("readiness confirms live before delivery", async () => {
    vi.useFakeTimers();
    try {
      const inspections = [{ present: false, state: "idle" }, { present: true, state: "idle" }];
      const session: TerminalSession = {
        inspect: vi.fn(async () => inspections.shift() || { present: true, state: "idle" }),
        input: vi.fn(async () => {}),
      };
      const ready = createTerminalDeliveryReadinessGate({ home: "/agent", session, inspectDelayMs: 5, coalesceMs: 0, rateLimitMs: 0 });
      let resolved = false;
      const waiting = ready("wake", new AbortController().signal).then(() => { resolved = true; });
      await flush();
      expect(resolved).toBe(false);
      await vi.advanceTimersByTimeAsync(5);
      await waiting;
      expect(resolved).toBe(true);
      expect(session.inspect).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  test("readiness treats stopped after live as inactive", async () => {
    vi.useFakeTimers();
    try {
      const inactive = vi.fn();
      const inspections = [{ present: true, state: "idle" }, { present: true, state: "stopped" }];
      const session: TerminalSession = {
        inspect: vi.fn(async () => inspections.shift() || { present: true, state: "stopped" }),
        input: vi.fn(async () => {}),
      };
      const ready = createTerminalDeliveryReadinessGate({ home: "/agent", session, onInactive: inactive, inspectDelayMs: 5, coalesceMs: 0, rateLimitMs: 0 });
      await ready("wake", new AbortController().signal);
      await expect(ready("wake", new AbortController().signal)).rejects.toBeInstanceOf(TerminalInactiveError);
      expect(inactive).toHaveBeenCalledWith("stopped");
    } finally {
      vi.useRealTimers();
    }
  });

  test("unknown readiness coalesces and rate-limits before fetch", async () => {
    vi.useFakeTimers();
    try {
      const session: TerminalSession = {
        inspect: vi.fn(async () => ({ present: true, state: "unknown" })),
        input: vi.fn(async () => {}),
      };
      const ready = createTerminalDeliveryReadinessGate({ home: "/agent", session, coalesceMs: 5, rateLimitMs: 20, inspectDelayMs: 1 });
      let firstResolved = false;
      const first = ready("wake", new AbortController().signal).then(() => { firstResolved = true; });
      await flush();
      expect(firstResolved).toBe(false);
      await vi.advanceTimersByTimeAsync(5);
      await first;

      let secondResolved = false;
      const second = ready("wake", new AbortController().signal).then(() => { secondResolved = true; });
      await flush();
      expect(secondResolved).toBe(false);
      await vi.advanceTimersByTimeAsync(20);
      await second;
    } finally {
      vi.useRealTimers();
    }
  });

  test("ambient awakenings are bounded and piggyback without initiating input", async () => {
    const inputs: string[] = [];
    const session: TerminalSession = {
      inspect: vi.fn(async () => ({ present: true, state: "idle" })),
      input: vi.fn(async (_home, text) => { inputs.push(text); }),
    };
    const handler = createTerminalAwakeningHandler({ home: "/agent", session, maxAmbient: 1 });
    let firstRejected = false;
    const first = handler(awakening({ kind: "work", content: "task-1", deliveryIntent: "ambient", meta: { type: "work", task_id: "t1" } }))
      .catch(() => { firstRejected = true; });
    const second = handler(awakening({ kind: "claim", content: "task-2", deliveryIntent: "ambient", meta: { type: "claim", task_id: "t2" } }));
    await flush();
    expect(session.input).not.toHaveBeenCalled();
    expect(firstRejected).toBe(true);
    expect(handler.status()).toEqual({ ambientQueued: 1, ambientDropped: 1 });

    const wake = handler(awakening({ content: "wake body" }));
    await Promise.all([first, second, wake]);
    expect(session.input).toHaveBeenCalledTimes(1);
    expect(inputs[0]).not.toContain("task_id: t1");
    expect(inputs[0]).toContain("task_id: t2");
    expect(inputs[0]).toContain("wake body");
    expect(handler.status()).toEqual({ ambientQueued: 0, ambientDropped: 1 });
  });

  test("input failure rejects instead of retrying held text", async () => {
    let attempts = 0;
    const session: TerminalSession = {
      inspect: vi.fn(async () => ({ present: true, state: "idle" })),
      input: vi.fn(async () => {
        attempts += 1;
        throw new Error("backend refused input");
      }),
    };
    const handler = createTerminalAwakeningHandler({ home: "/agent", session });
    await expect(handler(awakening())).rejects.toThrow("backend refused input");
    expect(session.input).toHaveBeenCalledTimes(1);
    expect(attempts).toBe(1);
  });

  test("aborting readiness while inspect is in flight prevents input", async () => {
    const abort = new AbortController();
    let finishInspect: (value: { present: boolean; state: string }) => void = () => {};
    const session: TerminalSession = {
      inspect: vi.fn(() => new Promise((resolve) => { finishInspect = resolve; })),
      input: vi.fn(async () => {}),
    };
    const ready = createTerminalDeliveryReadinessGate({ home: "/agent", session, coalesceMs: 0, rateLimitMs: 0 });
    const waiting = ready("wake", abort.signal);
    await flush();
    abort.abort();
    finishInspect({ present: true, state: "idle" });
    await expect(waiting).rejects.toThrow("terminal delivery aborted");
    expect(session.input).not.toHaveBeenCalled();
  });
});
