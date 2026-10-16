// The Claude Code hook-to-plugin path for agent activity (docs/agent-activity.md,
// "Emitters"). A Claude Code hook runs as a separate process; it forwards its
// event over a Unix socket to the aweb channel plugin of the same session. Both
// are children of one Claude Code process, so the plugin listens on a socket
// named by that pid, in a per-user directory only its owner can enter: the
// directory, not a peer-credential check, is what keeps other users out.
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, unlinkSync } from "node:fs";
import { createConnection, createServer, type Server } from "node:net";
import { join } from "node:path";

/** What a hook forwards: the event name, the tool name, and only the input fields summaries use. */
export interface HookEvent {
  hook_event_name: string;
  tool_name?: string;
  tool_input?: Record<string, string>;
}

/** The emitter calls a hook event can make. */
export interface HookEventTarget {
  turnStarted(): void;
  thinking(): void;
  tool(name: string, input: unknown): void;
  waitingPermission(name?: string): void;
  turnEnded(): void;
}

const SUMMARY_INPUT_KEYS = ["file_path", "notebook_path", "path", "command", "url"];
const MAX_FORWARDED_STRING = 4096;
const MAX_LINE_BYTES = 64 * 1024;
const CONNECT_TIMEOUT_MS = 300;

export function activitySocketDir(uid: number, platform: NodeJS.Platform = process.platform): string {
  return join(platform === "darwin" ? "/private/tmp" : "/tmp", `aweb-activity-${uid}`);
}

export function activitySocketPath(pid: number, dir: string): string {
  return join(dir, `${pid}.sock`);
}

/** Create the socket directory owner-only, or refuse one that is not. */
export function ensureOwnerOnlyDir(dir: string): void {
  try {
    mkdirSync(dir, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  const info = lstatSync(dir);
  if (info.isSymbolicLink()) throw new Error(`activity socket directory ${dir} is a symlink`);
  if (!info.isDirectory()) throw new Error(`activity socket directory ${dir} is not a directory`);
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error(`activity socket directory ${dir} belongs to another user`);
  }
  if ((info.mode & 0o077) !== 0) throw new Error(`activity socket directory ${dir} is not owner-only`);
}

/** The part of a Claude Code hook payload that crosses the socket, or undefined. */
export function hookEventForSocket(payload: unknown): HookEvent | undefined {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) return undefined;
  const fields = payload as Record<string, unknown>;
  if (typeof fields.hook_event_name !== "string" || !fields.hook_event_name) return undefined;
  const event: HookEvent = { hook_event_name: fields.hook_event_name };
  if (typeof fields.tool_name === "string") event.tool_name = fields.tool_name;
  const input = fields.tool_input;
  if (input !== null && typeof input === "object" && !Array.isArray(input)) {
    const kept: Record<string, string> = {};
    for (const key of SUMMARY_INPUT_KEYS) {
      const value = (input as Record<string, unknown>)[key];
      if (typeof value === "string") kept[key] = value.slice(0, MAX_FORWARDED_STRING);
    }
    if (Object.keys(kept).length > 0) event.tool_input = kept;
  }
  return event;
}

export function applyHookEvent(target: HookEventTarget, event: HookEvent): void {
  switch (event.hook_event_name) {
    case "UserPromptSubmit":
      target.turnStarted();
      break;
    case "PreToolUse":
      target.tool(event.tool_name ?? "unknown", event.tool_input ?? {});
      break;
    case "PermissionRequest":
      target.waitingPermission(event.tool_name);
      break;
    case "PostToolUse":
    case "PostToolUseFailure":
      target.thinking();
      break;
    case "Stop":
    case "StopFailure":
      target.turnEnded();
      break;
  }
}

function isLive(path: string): Promise<boolean> {
  return new Promise(resolve => {
    const socket = createConnection(path);
    const timer = setTimeout(() => { socket.destroy(); resolve(false); }, CONNECT_TIMEOUT_MS);
    socket.once("connect", () => { clearTimeout(timer); socket.destroy(); resolve(true); });
    socket.once("error", () => { clearTimeout(timer); resolve(false); });
  });
}

function handleLine(line: string, onEvent: (event: HookEvent) => void): void {
  if (!line || Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) return;
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return;
  }
  const event = hookEventForSocket(parsed);
  if (event !== undefined) onEvent(event);
}

/**
 * Listen for hook events on path. A stale socket file is replaced; a live
 * listener on the same path is never taken over.
 */
export async function listenForHookEvents(path: string, onEvent: (event: HookEvent) => void): Promise<Server> {
  if (existsSync(path)) {
    if (await isLive(path)) throw new Error(`an activity listener already serves ${path}`);
    unlinkSync(path);
  }
  const server = createServer(socket => {
    let buffer = "";
    let discarding = false;
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      let newline: number;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (discarding) {
          discarding = false;
          continue;
        }
        handleLine(line, onEvent);
      }
      if (Buffer.byteLength(buffer, "utf8") > MAX_LINE_BYTES) {
        buffer = "";
        discarding = true;
      }
    });
    socket.on("error", () => {});
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, () => {
      server.off("error", reject);
      resolve();
    });
  });
  chmodSync(path, 0o600);
  return server;
}

function send(path: string, line: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error("timeout")); }, CONNECT_TIMEOUT_MS);
    socket.once("connect", () => {
      socket.end(line, () => { clearTimeout(timer); resolve(); });
    });
    socket.once("error", (error) => { clearTimeout(timer); reject(error); });
  });
}

/**
 * Forward one event to the first candidate process with a live socket. Never
 * throws: activity is best-effort, and a hook must not fail a turn.
 */
export async function forwardHookEvent(
  event: HookEvent,
  options: { dir: string; candidates: Iterable<number> },
): Promise<void> {
  const line = `${JSON.stringify(event)}\n`;
  for (const pid of options.candidates) {
    const path = activitySocketPath(pid, options.dir);
    if (!existsSync(path)) continue;
    try {
      await send(path, line);
      return;
    } catch {
      continue;
    }
  }
}

/** This process's parent, then its ancestors, looked up only when asked for. */
export function* ancestorPids(start: number = process.ppid, depth: number = 4): Generator<number> {
  let pid = start;
  for (let level = 0; level < depth && pid > 1; level += 1) {
    yield pid;
    try {
      pid = Number(execFileSync("ps", ["-o", "ppid=", "-p", String(pid)], { timeout: 500 }).toString().trim());
    } catch {
      return;
    }
  }
}
