// The Claude Code hook-to-plugin path for agent activity (docs/agent-activity.md,
// "Emitters"): hooks forward their event over a per-user, owner-only socket
// keyed by the Claude Code process both share; the plugin maps it to the emitter.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import {
  activitySocketDir,
  activitySocketPath,
  createHookEventHandler,
  ensureOwnerOnlyDir,
  forwardHookEvent,
  hookEventForSocket,
  listenForHookEvents,
  removeDeadSockets,
  type HookEvent,
} from "../src/activity_socket.js";

let base: string;
beforeEach(() => { base = mkdtempSync(join(tmpdir(), "act-")); });
afterEach(() => { rmSync(base, { recursive: true, force: true }); });

describe("socket location", () => {
  test("is per user, under the system temp root, keyed by the Claude Code pid", () => {
    expect(activitySocketDir(501, "darwin")).toBe("/private/tmp/aweb-activity-501");
    expect(activitySocketDir(1000, "linux")).toBe("/tmp/aweb-activity-1000");
    expect(activitySocketPath(4242, "/tmp/aweb-activity-1000")).toBe("/tmp/aweb-activity-1000/4242.sock");
  });

  test("the directory is created owner-only", () => {
    const dir = join(base, "sockets");
    ensureOwnerOnlyDir(dir);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });

  test("a directory others can enter is refused", () => {
    const dir = join(base, "open");
    mkdirSync(dir, { mode: 0o755 });
    chmodSync(dir, 0o755);
    expect(() => ensureOwnerOnlyDir(dir)).toThrow(/owner-only/);
  });

  test("a symlinked directory is refused", () => {
    const real = join(base, "real");
    mkdirSync(real, { mode: 0o700 });
    const link = join(base, "link");
    symlinkSync(real, link);
    expect(() => ensureOwnerOnlyDir(link)).toThrow(/symlink/);
  });
});

describe("hook events", () => {
  test("only the fields the summaries use cross the socket", () => {
    const event = hookEventForSocket({
      session_id: "s", transcript_path: "/x", cwd: "/w", hook_event_name: "PreToolUse",
      tool_name: "Write", tool_use_id: "t",
      tool_input: { file_path: "/w/a.py", content: "SECRET FILE CONTENT", command: "make", url: "https://h/p", extra: 1 },
    });
    expect(event).toEqual({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "/w/a.py", command: "make", url: "https://h/p" },
    });
  });

  test("the prompt id crosses the socket, so events can be put in their turn", () => {
    expect(hookEventForSocket({ hook_event_name: "Stop", prompt_id: "p-1" })).toEqual({ hook_event_name: "Stop", prompt_id: "p-1" });
    expect(hookEventForSocket({ hook_event_name: "Stop", prompt_id: "x".repeat(200) })).toEqual({ hook_event_name: "Stop" });
  });

  test("a payload without an event name forwards nothing", () => {
    expect(hookEventForSocket({ tool_name: "Bash" })).toBeUndefined();
    expect(hookEventForSocket("not an object")).toBeUndefined();
  });

  test("each hook event maps to its phase", () => {
    const calls: unknown[][] = [];
    const target = {
      turnStarted: () => calls.push(["turnStarted"]),
      thinking: () => calls.push(["thinking"]),
      tool: (name: string, input: unknown) => calls.push(["tool", name, input]),
      waitingPermission: (name?: string) => calls.push(["waitingPermission", name]),
      turnEnded: () => calls.push(["turnEnded"]),
    };
    const events: HookEvent[] = [
      { hook_event_name: "UserPromptSubmit" },
      { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "pytest" } },
      { hook_event_name: "PermissionRequest", tool_name: "Bash" },
      { hook_event_name: "PostToolUse", tool_name: "Bash" },
      { hook_event_name: "PostToolUseFailure", tool_name: "Bash" },
      { hook_event_name: "Notification" },
      { hook_event_name: "Stop" },
      { hook_event_name: "StopFailure" },
    ];
    const handle = createHookEventHandler(target);
    events.forEach(handle);
    expect(calls).toEqual([
      ["turnStarted"],
      ["tool", "Bash", { command: "pytest" }],
      ["waitingPermission", "Bash"],
      ["thinking"],
      ["thinking"],
      ["turnEnded"],
      ["turnEnded"],
    ]);
  });
});

describe("listener and forwarding", () => {
  let server: Server | undefined;
  afterEach(async () => {
    await new Promise<void>(resolve => (server ? server.close(() => resolve()) : resolve()));
    server = undefined;
  });

  async function received(dir: string, pid: number, count: number, send: () => Promise<void>): Promise<HookEvent[]> {
    const events: HookEvent[] = [];
    let done: () => void = () => {};
    const all = new Promise<void>(resolve => { done = resolve; });
    server = await listenForHookEvents(activitySocketPath(pid, dir), (event) => {
      events.push(event);
      if (events.length === count) done();
    });
    await send();
    await Promise.race([all, new Promise(resolve => setTimeout(resolve, 2000))]);
    return events;
  }

  test("a forwarded hook event reaches the listener of its Claude Code process", async () => {
    const dir = join(base, "s");
    ensureOwnerOnlyDir(dir);
    const events = await received(dir, 4242, 1, () => forwardHookEvent(
      { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "pytest" } },
      { dir, candidates: [4242] },
    ));
    expect(events).toEqual([{ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "pytest" } }]);
  });

  test("forwarding finds the nearest ancestor that has a socket", async () => {
    const dir = join(base, "s");
    ensureOwnerOnlyDir(dir);
    const events = await received(dir, 77, 1, () => forwardHookEvent(
      { hook_event_name: "Stop" }, { dir, candidates: [11, 77, 99] },
    ));
    expect(events).toEqual([{ hook_event_name: "Stop" }]);
  });

  test("with no socket, forwarding returns quietly", async () => {
    const dir = join(base, "s");
    ensureOwnerOnlyDir(dir);
    await expect(forwardHookEvent({ hook_event_name: "Stop" }, { dir, candidates: [1, 2] })).resolves.toBeUndefined();
  });

  test("malformed and oversized lines are ignored; later events still arrive", async () => {
    const dir = join(base, "s");
    ensureOwnerOnlyDir(dir);
    const events = await received(dir, 5, 1, async () => {
      const { createConnection } = await import("node:net");
      await new Promise<void>((resolve, reject) => {
        const socket = createConnection(activitySocketPath(5, dir), () => {
          socket.write("not json\n");
          socket.write(`${JSON.stringify({ hook_event_name: "PreToolUse", tool_input: { command: "x".repeat(70_000) } })}\n`);
          socket.end(`${JSON.stringify({ hook_event_name: "Stop" })}\n`);
        });
        socket.on("close", () => resolve());
        socket.on("error", reject);
      });
    });
    expect(events).toEqual([{ hook_event_name: "Stop" }]);
  });

  test("a stale socket file is replaced", async () => {
    const dir = join(base, "s");
    ensureOwnerOnlyDir(dir);
    writeFileSync(activitySocketPath(6, dir), "");
    const events = await received(dir, 6, 1, () => forwardHookEvent({ hook_event_name: "Stop" }, { dir, candidates: [6] }));
    expect(events).toEqual([{ hook_event_name: "Stop" }]);
  });

  test("a live socket is never taken over", async () => {
    const dir = join(base, "s");
    ensureOwnerOnlyDir(dir);
    const path = activitySocketPath(8, dir);
    const live = createServer();
    await new Promise<void>(resolve => live.listen(path, resolve));
    try {
      await expect(listenForHookEvents(path, () => {})).rejects.toThrow(/already/);
    } finally {
      await new Promise<void>(resolve => live.close(() => resolve()));
    }
  });

  test("the socket file is owner-only", async () => {
    const dir = join(base, "s");
    ensureOwnerOnlyDir(dir);
    server = await listenForHookEvents(activitySocketPath(9, dir), () => {});
    expect(statSync(activitySocketPath(9, dir)).mode & 0o777).toBe(0o600);
  });
});

describe("dead sockets", () => {
  test("sockets of processes that no longer run are removed; live ones and other files are kept", () => {
    const dir = join(base, "s");
    ensureOwnerOnlyDir(dir);
    const dead = 2_147_483_000;
    writeFileSync(activitySocketPath(dead, dir), "");
    writeFileSync(activitySocketPath(process.pid, dir), "");
    writeFileSync(join(dir, "notes.txt"), "");

    removeDeadSockets(dir);

    expect(existsSync(activitySocketPath(dead, dir))).toBe(false);
    expect(existsSync(activitySocketPath(process.pid, dir))).toBe(true);
    expect(existsSync(join(dir, "notes.txt"))).toBe(true);
  });
});

describe("hook events out of order", () => {
  // Each hook is its own process, so their arrival is not ordered (fix-review
  // 443a4345 A1). The prompt id puts each event in its turn.
  function recorder() {
    const calls: string[] = [];
    const target = {
      turnStarted: () => calls.push("turnStarted"),
      thinking: () => calls.push("thinking"),
      tool: (name: string) => calls.push(`tool:${name}`),
      waitingPermission: () => calls.push("waitingPermission"),
      turnEnded: () => calls.push("turnEnded"),
    };
    return { handle: createHookEventHandler(target), calls };
  }

  test("an event of a prompt that has stopped is dropped", () => {
    const { handle, calls } = recorder();
    handle({ hook_event_name: "UserPromptSubmit", prompt_id: "p1" });
    handle({ hook_event_name: "Stop", prompt_id: "p1" });
    handle({ hook_event_name: "PostToolUse", tool_name: "Bash", prompt_id: "p1" });
    handle({ hook_event_name: "PreToolUse", tool_name: "Bash", prompt_id: "p1" });
    expect(calls).toEqual(["turnStarted", "turnEnded"]);
  });

  test("a tool event before its own prompt's submit makes one turn, not two", () => {
    const { handle, calls } = recorder();
    handle({ hook_event_name: "PreToolUse", tool_name: "Read", prompt_id: "p1" });
    handle({ hook_event_name: "UserPromptSubmit", prompt_id: "p1" });
    handle({ hook_event_name: "Stop", prompt_id: "p1" });
    expect(calls).toEqual(["tool:Read", "turnEnded"]);
  });

  test("a turn opened without a submit, as a chat wake may, still publishes", () => {
    const { handle, calls } = recorder();
    handle({ hook_event_name: "PreToolUse", tool_name: "Bash", prompt_id: "p1" });
    handle({ hook_event_name: "PostToolUse", tool_name: "Bash", prompt_id: "p1" });
    handle({ hook_event_name: "Stop", prompt_id: "p1" });
    expect(calls).toEqual(["tool:Bash", "thinking", "turnEnded"]);
  });

  test("a new prompt closes a turn whose stop never arrived", () => {
    const { handle, calls } = recorder();
    handle({ hook_event_name: "UserPromptSubmit", prompt_id: "p1" });
    handle({ hook_event_name: "PreToolUse", tool_name: "Bash", prompt_id: "p2" });
    expect(calls).toEqual(["turnStarted", "turnEnded", "tool:Bash"]);
  });

  test("a straggler of an ended prompt is dropped while the next one runs", () => {
    const { handle, calls } = recorder();
    handle({ hook_event_name: "UserPromptSubmit", prompt_id: "p1" });
    handle({ hook_event_name: "Stop", prompt_id: "p1" });
    handle({ hook_event_name: "UserPromptSubmit", prompt_id: "p2" });
    handle({ hook_event_name: "PostToolUse", tool_name: "Bash", prompt_id: "p1" });
    handle({ hook_event_name: "Stop", prompt_id: "p2" });
    expect(calls).toEqual(["turnStarted", "turnEnded", "turnStarted", "turnEnded"]);
  });
});

