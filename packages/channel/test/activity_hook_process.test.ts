// The packaged hook runner as Claude Code runs it: a child process whose parent
// is the session's Claude Code process. Here the test process plays that parent
// and listens on its own pid's socket in the real per-user directory.
import { spawn } from "node:child_process";
import { existsSync, unlinkSync } from "node:fs";
import type { Server } from "node:net";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "vitest";
import {
  activitySocketDir,
  activitySocketPath,
  ensureOwnerOnlyDir,
  listenForHookEvents,
  type HookEvent,
} from "../src/activity_socket.js";

const HOOK = fileURLToPath(new URL("../dist/activity-hook.js", import.meta.url));
const DIR = activitySocketDir(process.getuid!());
const SOCKET = activitySocketPath(process.pid, DIR);

function runHook(stdin: string): Promise<{ code: number | null; stdout: string; ms: number }> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawn(process.execPath, [HOOK], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", chunk => (stdout += chunk));
    child.on("error", reject);
    child.on("close", code => resolve({ code, stdout, ms: Date.now() - started }));
    child.stdin.end(stdin);
  });
}

let server: Server | undefined;
afterEach(async () => {
  await new Promise<void>(resolve => (server ? server.close(() => resolve()) : resolve()));
  server = undefined;
  if (existsSync(SOCKET)) unlinkSync(SOCKET);
});

describe("activity hook runner", () => {
  test("forwards a stripped event to its parent's socket, silently", async () => {
    ensureOwnerOnlyDir(DIR);
    const received: HookEvent[] = [];
    server = await listenForHookEvents(SOCKET, event => received.push(event));

    const result = await runHook(JSON.stringify({
      session_id: "s", hook_event_name: "PreToolUse", tool_name: "Write",
      tool_input: { file_path: "/w/a.py", content: "SECRET FILE CONTENT" },
    }));
    await new Promise(resolve => setTimeout(resolve, 100));

    expect(result).toMatchObject({ code: 0, stdout: "" });
    expect(received).toEqual([{ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: "/w/a.py" } }]);
  });

  test("with no listener it exits 0 quickly and silently", async () => {
    const result = await runHook(JSON.stringify({ hook_event_name: "Stop" }));
    expect(result.code).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.ms).toBeLessThan(3000);
  });

  test.each([["invalid JSON", "{"], ["no event name", "{}"], ["empty input", ""]])("%s exits 0 silently", async (_name, stdin) => {
    const result = await runHook(stdin);
    expect(result).toMatchObject({ code: 0, stdout: "" });
  });
});
