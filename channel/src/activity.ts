import { createClaudeChannelClient } from "./client.js";
// Agent activity for a Claude Code session (docs/agent-activity.md, "Emitters"):
// the plugin owns the session's emitter and listens for its hooks.
import { unlinkSync } from "node:fs";
import {
  createActivityEmitter,
  endActivity,
  type ActivityEmitter,
  type AgentConfig,
} from "@awebai/channel-core";
import {
  activitySocketDir,
  activitySocketPath,
  createHookEventHandler,
  ensureOwnerOnlyDir,
  listenForHookEvents,
  removeDeadSockets,
} from "./activity_socket.js";

export interface ClaudeActivity {
  emitter: ActivityEmitter;
  /** Close the hook socket, then end and flush the open turn (bounded). */
  stop(): Promise<void>;
}

/**
 * Start the session's activity: the emitter, and the hook socket named by the
 * Claude Code process (this plugin's parent). Any failure leaves activity off
 * for the session, with one log line.
 */
export async function startClaudeActivity(
  config: AgentConfig,
  workdir: string,
  options: { claudePid?: number; dir?: string; log?: (line: string) => void } = {},
): Promise<ClaudeActivity | undefined> {
  const log = options.log ?? ((line: string) => console.error(line));
  try {
    if (typeof process.getuid !== "function") throw new Error("this platform has no per-user socket directory");
    const emitter = createActivityEmitter(config, createClaudeChannelClient(config), { workRoot: workdir, log });
    const dir = options.dir ?? activitySocketDir(process.getuid());
    ensureOwnerOnlyDir(dir);
    removeDeadSockets(dir);
    const path = activitySocketPath(options.claudePid ?? process.ppid, dir);
    const server = await listenForHookEvents(path, createHookEventHandler(emitter));
    return {
      emitter,
      stop: async () => {
        await new Promise<void>(resolve => server.close(() => resolve()));
        try {
          unlinkSync(path);
        } catch {
          // Already gone.
        }
        await endActivity(emitter);
      },
    };
  } catch (error) {
    log(`aweb activity is off for this session: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
}
