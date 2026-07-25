import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";

import type { ChatMessage } from "./api/chat.js";
import type { InboxMessage } from "./api/mail.js";
import type { PinStoreWriter } from "./identity/pinstore.js";

const execFileAsync = promisify(execFile);

export interface LocalDecryptProvider {
  mailMessage?(messageID: string): Promise<Partial<InboxMessage> | null>;
  chatMessage?(sessionID: string, messageID: string): Promise<Partial<ChatMessage> | null>;
}

export interface LocalAWDecryptOptions {
  workdir: string;
  awCommand?: string;
}

export interface LocalAWPinStoreOptions {
  workdir?: string;
  awCommand?: string;
}

export function createLocalAWPinStoreWriter(options: LocalAWPinStoreOptions = {}): PinStoreWriter {
  const awCommand = options.awCommand || process.env.AW_BIN || "aw";
  return {
    async compareAndSet(path: string, expectedYAML: string, desiredYAML: string): Promise<void> {
      await execFileWithInput(
        awCommand,
        ["id", "pin-store", "compare-and-set", "--path", path],
        `${JSON.stringify({ expected_yaml: expectedYAML, desired_yaml: desiredYAML })}\n`,
        options.workdir || process.cwd(),
      );
    },
  };
}

export function createLocalAWDecryptProvider(options: LocalAWDecryptOptions): LocalDecryptProvider {
  const awCommand = options.awCommand || process.env.AW_BIN || "aw";
  return {
    async mailMessage(messageID: string): Promise<Partial<InboxMessage> | null> {
      const id = messageID.trim();
      if (!id) return null;
      const { stdout } = await execFileAsync(
        awCommand,
        ["mail", "show", "--message-id", id, "--json"],
        { cwd: options.workdir, timeout: 15_000, maxBuffer: 1024 * 1024 },
      );
      const payload = parseJSONOutput<{ messages?: InboxMessage[] }>(stdout);
      return (payload.messages || []).find((msg) => msg.message_id === id) || null;
    },
    async chatMessage(sessionID: string, messageID: string): Promise<Partial<ChatMessage> | null> {
      const session = sessionID.trim();
      const id = messageID.trim();
      if (!session || !id) return null;
      const { stdout } = await execFileAsync(
        awCommand,
        ["chat", "history", "--session-id", session, "--message-id", id, "--limit", "1", "--json"],
        { cwd: options.workdir, timeout: 15_000, maxBuffer: 1024 * 1024 },
      );
      const payload = parseJSONOutput<{ messages?: ChatMessage[] }>(stdout);
      return (payload.messages || []).find((msg) => msg.message_id === id) || null;
    },
  };
}

function execFileWithInput(command: string, args: string[], input: string, cwd: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const appendBounded = (current: string, chunk: Buffer): string => {
      const next = current + chunk.toString("utf-8");
      return next.length > 1024 * 1024 ? next.slice(-(1024 * 1024)) : next;
    };
    child.stdout.on("data", (chunk: Buffer) => { stdout = appendBounded(stdout, chunk); });
    child.stderr.on("data", (chunk: Buffer) => { stderr = appendBounded(stderr, chunk); });
    child.on("error", (error) => finish(new Error(`cannot execute aw pin-store writer: ${error.message}`)));
    child.on("close", (code, signal) => {
      if (code === 0) {
        finish();
        return;
      }
      const detail = stderr.trim() || stdout.trim() || `exit ${code ?? signal ?? "unknown"}`;
      finish(new Error(`aw refused pin-store mutation: ${detail}`));
    });
    child.stdin.on("error", (error) => finish(new Error(`cannot send pin-store mutation to aw: ${error.message}`)));
    child.stdin.end(input, "utf-8");
    timer = setTimeout(() => {
      child.kill();
      finish(new Error("aw pin-store mutation timed out"));
    }, 15_000);
  });
}

function parseJSONOutput<T>(stdout: string): T {
  const trimmed = stdout.trim();
  if (!trimmed) throw new Error("aw returned empty JSON output");
  const start = trimmed.indexOf("{");
  if (start < 0) throw new Error("aw JSON output did not contain an object");
  return JSON.parse(trimmed.slice(start)) as T;
}
