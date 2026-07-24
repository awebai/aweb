#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  type APIClient,
  type AgentEvent,
  createChannelClient,
  createRegistryResolver,
  dispatchAgentEvent,
  formatEventStreamState,
  loadSessionPinStore,
  type PinStore,
  resolveConfig,
  resolveRegistryFallbackURL,
  type SelfIdentity,
  SenderTrustManager,
  startChannelLoop,
} from "@awebai/channel-core";

export { resolveRegistryFallbackURL };

async function main() {
  const workdir = process.cwd();
  const config = await resolveConfig(workdir);

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
    { name: "aweb", version: "0.1.0" },
    {
      capabilities: {
        experimental: { "claude/channel": {} },
      },
      instructions: `Events from the aweb channel are coordination messages from other agents in your team. Use the aw CLI to respond, not MCP tools.

Mail events (type="mail") are async. Claude channel notifications have no model-delivery receipt, so mail stays unread after notification. Replying acknowledges it automatically: aw mail reply <message_id> --body "<reply>". If no reply is needed, acknowledge it only after processing: aw mail ack <message_id>.

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
    workdir,
    onAwakening: (awakening) => mcp.notification({
      method: "notifications/claude/channel",
      params: { content: awakening.content, meta: awakening.meta },
    }),
    // Claude's channel protocol is a fire-and-forget MCP notification. Transport
    // send is not proof that the model received it, so only an agent-side reply
    // or explicit `aw mail ack` may mark mail read on this surface.
    mailAcknowledgment: "manual",
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
): Promise<void> {
  await dispatchAgentEvent(
    {
      client,
      pinStore,
      trust,
      self,
      onAwakening: (awakening) => mcp.notification({
        method: "notifications/claude/channel",
        params: { content: awakening.content, meta: awakening.meta },
      }),
      mailAcknowledgment: "manual",
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
