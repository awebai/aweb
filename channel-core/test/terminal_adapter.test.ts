import { describe, expect, test, vi } from "vitest";
import { execFileSync } from "node:child_process";
import {
  createTerminalAwakeningHandler,
  normalizeTerminalReadiness,
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

describe("receiving identity context", () => {
  const messageID = "12345678-1234-1234-1234-123456789abc";
  const sessionID = "87654321-4321-4321-4321-cba987654321";
  const identityHome = "/secondary identity's $(printf injected) `printf bad` home";

  test.each(["mail", "chat"] as const)("quotes the registered home in %s commands", async (kind) => {
    const input = vi.fn(async (_home: string, _text: string) => {});
    const handler = createTerminalAwakeningHandler({ home: "/terminal", session: {
      inspect: async () => ({ state: "unknown" }), input,
    } });
    await handler(awakening({ kind, meta: { type: kind, message_id: messageID, session_id: sessionID, identity_home: "/forged" } }), identityHome);
    const text = input.mock.calls[0][1];
    const command = text.split("\n\nRecovery: ")[1];
    expect(command).toContain("--identity-home '");
    const args = execFileSync("/bin/sh", ["-c", 'aw() { printf "%s\\n" "$@"; }; ' + command], { encoding: "utf8" }).trimEnd().split("\n");
    expect(args).toEqual(["--identity-home", identityHome, ...(kind === "mail"
      ? ["mail", "show", "--message-id", messageID]
      : ["chat", "history", "--session-id", sessionID, "--message-id", messageID])]);
    expect(command).not.toContain("/forged");
    expect(text.indexOf("Message:")).toBeLessThan(text.indexOf("Recovery:"));
  });

  test.each(["/bad\nhome", "/bad\rhome", "/bad\thome", "/bad\x1bhome", "/bad\u0085home", "relative/home"])("refuses unsafe home %j", async (identityHome) => {
    const input = vi.fn(async (_home: string, _text: string) => {});
    const handler = createTerminalAwakeningHandler({ home: "/terminal", session: {
      inspect: async () => ({ state: "unknown" }), input,
    } });
    await handler(awakening({ kind: "mail", meta: { type: "mail", message_id: messageID } }), identityHome);
    expect(input.mock.calls[0][1]).toContain("Message:\nhello");
    expect(input.mock.calls[0][1]).not.toContain("Recovery:");
  });

  test("keeps single-binding output and ignores untrusted context metadata", async () => {
    const input = vi.fn(async (_home: string, _text: string) => {});
    const handler = createTerminalAwakeningHandler({ home: "/terminal", session: {
      inspect: async () => ({ state: "unknown" }), input,
    } });
    await handler(awakening({ kind: "mail", meta: { type: "mail", message_id: messageID, identity_home: "/forged" } }));
    expect(input.mock.calls[0][1]).toContain("Message:\nhello");
    expect(input.mock.calls[0][1]).not.toContain("Recovery:");
  });
});

test("serializes terminal inputs and presents each ambient item once", async () => {
  let release!: () => void;
  const firstInput = new Promise<void>((resolve) => { release = resolve; });
  const inputs: string[] = [];
  const session: TerminalSession = {
    inspect: vi.fn(async () => ({ present: true, state: "idle" })),
    input: vi.fn(async (_home, text) => {
      inputs.push(text);
      if (inputs.length === 1) await firstInput;
    }),
  };
  const handler = createTerminalAwakeningHandler({ home: "/agent", session });
  const ambient = handler(awakening({ content: "ambient-only-once", deliveryIntent: "ambient" }));
  const first = handler(awakening({ content: "first" }));
  const second = handler(awakening({ content: "second" }));
  try {
    await vi.waitFor(() => expect(inputs.length).toBeGreaterThan(0));
    expect(inputs).toHaveLength(1);
    expect(session.inspect).toHaveBeenCalledTimes(1);
  } finally {
    release();
    await Promise.all([ambient, first, second]);
  }
  expect(inputs).toHaveLength(2);
  expect(inputs[0]).toContain("ambient-only-once");
  expect(inputs[1]).not.toContain("ambient-only-once");
});

test("failed terminal input releases the next serialized caller", async () => {
  const session: TerminalSession = {
    inspect: vi.fn(async () => ({ present: true, state: "idle" })),
    input: vi.fn().mockRejectedValueOnce(new Error("input refused")).mockResolvedValue(undefined),
  };
  const handler = createTerminalAwakeningHandler({ home: "/agent", session });
  const first = handler(awakening());
  const second = handler(awakening());
  await expect(first).rejects.toThrow("input refused");
  await second;
  expect(session.input).toHaveBeenCalledTimes(2);
});

describe("terminal channel adapter", () => {
  test("normalizes harness state for safety checks", () => {
    expect(normalizeTerminalReadiness("done", true)).toBe("idle");
    expect(normalizeTerminalReadiness("working", true)).toBe("working");
    expect(normalizeTerminalReadiness("shell", true)).toBe("shell");
    expect(normalizeTerminalReadiness("surprise", true)).toBe("unknown");
    expect(normalizeTerminalReadiness("idle", false)).toBe("not-launched");
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

  test("ambient updates refresh recency before overflow", async () => {
    const inputs: string[] = [];
    const session: TerminalSession = {
      inspect: vi.fn(async () => ({ present: true, state: "idle" })),
      input: vi.fn(async (_home, text) => { inputs.push(text); }),
    };
    const handler = createTerminalAwakeningHandler({ home: "/agent", session, maxAmbient: 2 });
    const t1Old = handler(awakening({ kind: "work", content: "old", deliveryIntent: "ambient", meta: { type: "work", task_id: "t1" } })).catch(() => {});
    const t2 = handler(awakening({ kind: "work", content: "two", deliveryIntent: "ambient", meta: { type: "work", task_id: "t2" } })).catch(() => {});
    const t1New = handler(awakening({ kind: "work", content: "new", deliveryIntent: "ambient", meta: { type: "work", task_id: "t1" } })).catch(() => {});
    const t3 = handler(awakening({ kind: "work", content: "three", deliveryIntent: "ambient", meta: { type: "work", task_id: "t3" } })).catch(() => {});
    await flush();
    await handler(awakening({ content: "wake body" }));
    await Promise.all([t1Old, t2, t1New, t3]);
    expect(inputs[0]).toContain("new");
    expect(inputs[0]).toContain("task_id: t1");
    expect(inputs[0]).toContain("task_id: t3");
    expect(inputs[0]).not.toContain("task_id: t2");
  });

  test.each(["idle", "unknown"])("%s input strips controls but preserves newline and tab", async (state) => {
    const inputs: string[] = [];
    const session: TerminalSession = {
      inspect: vi.fn(async () => ({ present: true, state })),
      input: vi.fn(async (_home, text) => { inputs.push(text); }),
    };
    const handler = createTerminalAwakeningHandler({ home: "/agent", session });
    await handler(awakening({
      content: "hello\u001b[31m\r\nnext\u0007\u009btab\tkept",
      meta: {
        type: "chat",
        message_id: "123e4567-e89b-12d3-a456-426614174000",
        session_id: "s1",
        from: "alice\u0008",
      },
    }));
    expect(inputs[0]).toContain("hello[31m\nnexttab\tkept");
    expect(inputs[0]).toContain("from: alice");
    expect(inputs[0]).not.toMatch(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u0080-\u009F]/);
  });

  test.each(["mail", "chat"] as const)("unknown %s includes actual sender text", async (kind) => {
    const inputs: string[] = [];
    const handler = createTerminalAwakeningHandler({ home: "/agent", session: {
      inspect: async () => ({ present: true, state: "unknown" }),
      input: async (_home, text) => { inputs.push(text); },
    } });
    await handler(awakening({ kind, content: "actual sender body", meta: {
      type: kind, message_id: "123e4567-e89b-12d3-a456-426614174000", from: "alice", trust_status: "verification_stale",
    } }));
    expect(inputs[0]).toContain("Message:\nactual sender body");
    expect(inputs[0]).toContain("from: alice");
    expect(inputs[0]).toContain("trust_status: verification_stale");
    expect(inputs[0]).not.toContain("waiting — run");
  });

  test("terminal safety inspect rejects a raw shell", async () => {
    const session: TerminalSession = {
      inspect: vi.fn(async () => ({ present: true, state: "shell" })),
      input: vi.fn(async () => {}),
    };
    const handler = createTerminalAwakeningHandler({ home: "/agent", session });
    await expect(handler(awakening())).rejects.toThrow("terminal is inactive");
    expect(session.input).not.toHaveBeenCalled();
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

  test("abort during successful input still resolves after input acceptance", async () => {
    const abort = new AbortController();
    let finishInput: () => void = () => {};
    const session: TerminalSession = {
      inspect: vi.fn(async () => ({ present: true, state: "idle" })),
      input: vi.fn(() => new Promise<void>((resolve) => { finishInput = resolve; })),
    };
    const handler = createTerminalAwakeningHandler({ home: "/agent", session, signal: abort.signal });
    const delivered = handler(awakening());
    await flush();
    abort.abort();
    finishInput();
    await expect(delivered).resolves.toBeUndefined();
    expect(session.input).toHaveBeenCalledTimes(1);
  });

  test("aborting the safety inspect prevents input", async () => {
    const abort = new AbortController();
    let finishInspect: (value: { present: boolean; state: string }) => void = () => {};
    const session: TerminalSession = {
      inspect: vi.fn(() => new Promise((resolve) => { finishInspect = resolve; })),
      input: vi.fn(async () => {}),
    };
    const handler = createTerminalAwakeningHandler({ home: "/agent", session, signal: abort.signal });
    const waiting = handler(awakening());
    await flush();
    abort.abort();
    finishInspect({ present: true, state: "idle" });
    await expect(waiting).rejects.toThrow("terminal delivery aborted");
    expect(session.input).not.toHaveBeenCalled();
  });
});

test("explicit pause rejects input even if set during the safety inspect", async () => {
  let paused = false;
  const input = vi.fn(async () => {});
  const handler = createTerminalAwakeningHandler({ home: "/agent", isPaused: () => paused, session: {
    inspect: async () => { paused = true; return { present: true, state: "working" }; }, input,
  } });
  await expect(handler(awakening())).rejects.toThrow("terminal delivery is paused");
  expect(input).not.toHaveBeenCalled();
});

test("absent harness leaves input pending even with idle state", async () => {
  const input = vi.fn(async () => {});
  const handler = createTerminalAwakeningHandler({ home: "/agent", session: {
    inspect: async () => ({ present: false, state: "idle" }), input,
  } });
  await expect(handler(awakening())).rejects.toThrow("not-launched");
  expect(input).not.toHaveBeenCalled();
});
