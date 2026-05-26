import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { ChatMessage } from "./api/chat.js";
import type { InboxMessage } from "./api/mail.js";

const execFileAsync = promisify(execFile);

export interface LocalDecryptProvider {
  mailMessage?(messageID: string): Promise<Partial<InboxMessage> | null>;
  chatMessage?(sessionID: string, messageID: string): Promise<Partial<ChatMessage> | null>;
}

export interface LocalAWDecryptOptions {
  workdir: string;
  awCommand?: string;
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

function parseJSONOutput<T>(stdout: string): T {
  const trimmed = stdout.trim();
  if (!trimmed) throw new Error("aw returned empty JSON output");
  const start = trimmed.indexOf("{");
  if (start < 0) throw new Error("aw JSON output did not contain an object");
  return JSON.parse(trimmed.slice(start)) as T;
}
