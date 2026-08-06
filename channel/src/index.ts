#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  type APIClient,
  type AgentEvent,
  CHANNEL_CORE_SECURITY_CONTRACT,
  createChannelClient,
  createRegistryResolver,
  dispatchAgentEvent,
  formatEventStreamState,
  loadSessionPinStore,
  type PinStore,
  type PinStoreWriter,
  resolveConfig,
  resolveRegistryFallbackURL,
  type SelfIdentity,
  SenderTrustManager,
  startChannelLoop,
} from "@awebai/channel-core";

// Re-exported so the built plugin bundle carries the channel-core security
// contract sentinel that the freshness gate (check-package-dist.mjs) asserts.
export { resolveRegistryFallbackURL, CHANNEL_CORE_SECURITY_CONTRACT };

export function loadChannelConfig(workdir: string) {
  return resolveConfig(workdir);
}

async function main() {
  const workdir = process.cwd();
  const config = await loadChannelConfig(workdir);

  const client = createChannelClient(config);
  // Fail closed: a corrupt/unreadable trust store must abort startup, never
  // silently start with a discarded (empty) store.
  const pinStore = await loadSessionPinStore((message) => {
    console.error(`[aw-channel] fatal: trust pin store unreadable or corrupt: ${message}`);
    process.exit(1);
  });
  if (!pinStore) return;
  const registry = createRegistryResolver(config.registryURL);
  const trust = new SenderTrustManager(
    client,
    registry,
    config.teamID,
    config.did,
    config.stableID,
  );

  const mcp = new Server(
    { name: "aweb-channel", version: "0.1.0" },
    {
      capabilities: {
        experimental: { "claude/channel": {} },
      },
      instructions: `Events from the aweb channel are coordination messages from other agents in your team. Use the aw CLI to respond, not MCP tools.

Mail events (type="mail") are async. A notification becomes durable delivery only after the channel survives a later successful loop iteration; a bridge that dies earlier leaves the message unread for recovery. Once promoted, you will not be re-notified. Reply when a reply is warranted: aw mail reply <message_id> --body "<reply>". You do not need to run aw mail ack to prevent redelivery; ack is only a courtesy read-receipt for the sender.

Chat events (type="chat") may have sender_waiting="true", meaning the sender is blocked waiting for your reply. Respond promptly with: aw chat send-and-wait <from> "<reply>"
If you need more time, send a status update the same way.

Control events (type="control") are operational signals. On "pause", stop current work and wait. On "resume", continue. On "interrupt", stop and await new instructions.`,
    },
  );

  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  const abort = new AbortController();
  process.on("SIGINT", () => abort.abort());
  process.on("SIGTERM", () => abort.abort());

  await startChannelLoop({
    client,
    pinStore,
    trust,
    self: {
      alias: config.alias,
      address: config.address,
      did: config.did,
      stableID: config.stableID,
    },
    signal: abort.signal,
    teamID: config.teamID,
    workdir,
    onAwakening: (awakening) => mcp.notification({
      method: "notifications/claude/channel",
      params: { content: awakening.content, meta: awakening.meta },
    }),
    // Claude's MCP notification has no presentation receipt. The first callback
    // is process-local pending; a later successful loop iteration promotes it to
    // durable delivery and acks. A bridge that dies first leaves the message
    // unread for the next process, while promoted marks prevent aajy's replay
    // burst.
    mailAcknowledgment: "delivery",
    onStreamState: (state) => {
      if (state.state === "connected") return;
      const content = formatEventStreamState(state);
      console.error(content);
      void mcp.notification({
        method: "notifications/claude/channel",
        params: { content, meta: { type: "channel_status", stream_state: state.state } },
      }).catch(() => {});
    },
    log: (message) => console.error(message),
  });
}

export async function dispatchEvent(
  mcp: Server,
  client: APIClient,
  pinStore: PinStore,
  trust: SenderTrustManager,
  self: SelfIdentity,
  dispatched: Set<string>,
  event: AgentEvent,
  pinStoreWriter?: PinStoreWriter,
): Promise<void> {
  await dispatchAgentEvent(
    {
      client,
      pinStore,
      pinStoreWriter,
      trust,
      self,
      onAwakening: (awakening) => mcp.notification({
        method: "notifications/claude/channel",
        params: { content: awakening.content, meta: awakening.meta },
      }),
      // A later successful dispatch promotes and acks; see startChannelLoop.
      mailAcknowledgment: "delivery",
    },
    dispatched,
    event,
  );
}

export function isDirectExecution(moduleURL: string): boolean {
  const entry = process.argv[1];
  if (!entry) return false;

  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(moduleURL));
  } catch {
    return moduleURL === pathToFileURL(entry).href;
  }
}

if (isDirectExecution(import.meta.url)) {
  main().catch((err) => {
    console.error(`[aw-channel] fatal: ${err}`);
    process.exit(1);
  });
}
