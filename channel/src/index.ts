#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { realpathSync } from "node:fs";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
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
  type ChannelTraceEntry,
  type RegistryIdentityConfig,
  type ResolveTxt,
  resolveConfig,
  resolveRegistryFallbackURL,
  type SelfIdentity,
  selectDeliveryMode,
  type DeliveryMode,
  SenderTrustManager,
  startChannelLoop,
} from "@awebai/channel-core";

// Re-exported so the built plugin bundle carries the channel-core security
// contract sentinel that the freshness gate (check-package-dist.mjs) asserts.
export { resolveRegistryFallbackURL, CHANNEL_CORE_SECURITY_CONTRACT };

export function loadChannelConfig(workdir: string) {
  return resolveConfig(workdir);
}

/**
 * The single line this plugin prints at startup when AWEB_DELIVERY=session.
 * Delivery belongs to something else on the host, so the plugin registers no
 * channel and opens no event stream.
 */
export const CHANNEL_EXTERNAL_DELIVERY_NOTICE =
  "[aw-channel] AWEB_DELIVERY=session — delivery is external. This plugin will not open the aweb event stream or deliver channel notifications; identity, the bundled aweb skills, and the aw CLI stay available.";

const CHANNEL_EXTERNAL_DELIVERY_INSTRUCTIONS =
  "aweb delivery is external for this session (AWEB_DELIVERY=session). This plugin delivers nothing: mail, chat, control signals, work and claim updates reach you through the host's own wake path. Use the aw CLI to read and respond: aw mail inbox, aw chat pending, aw workspace status.";

export interface ChannelDeliveryDecision {
  mode: DeliveryMode;
  /** Reported once when AWEB_DELIVERY held a value this build does not know. */
  warning?: string;
  /** The one startup line; set only when delivery is external. */
  notice?: string;
}

/**
 * Decide, from the environment, whether this plugin delivers aweb events
 * itself. main() consumes this before it registers the channel.
 */
export function resolveChannelDelivery(env: NodeJS.ProcessEnv = process.env): ChannelDeliveryDecision {
  const selection = selectDeliveryMode(env);
  if (selection.mode === "session") {
    return { mode: "session", notice: CHANNEL_EXTERNAL_DELIVERY_NOTICE };
  }
  return selection.warning ? { mode: "channel", warning: selection.warning } : { mode: "channel" };
}

type ChannelServerOptions = NonNullable<ConstructorParameters<typeof Server>[1]>;

function createChannelMCPServer(options: ChannelServerOptions): Server {
  return new Server({ name: "aweb-channel", version: "0.1.0" }, options);
}

export function createChannelRegistryResolver(
  config: RegistryIdentityConfig,
  resolveTxt?: ResolveTxt,
) {
  return createRegistryResolver(config, resolveTxt);
}

export interface ChannelTraceSink {
  onTrace: (entry: ChannelTraceEntry) => void;
  flush: () => Promise<void>;
}

type AppendTrace = (path: string, line: string) => Promise<void>;

export function createChannelTraceSink(
  debug = process.env.AWEB_CHANNEL_DEBUG || "",
  path = process.env.AWEB_CHANNEL_DEBUG_FILE || "",
  append: AppendTrace = (target, line) => appendFile(
    target,
    line,
    { encoding: "utf-8", mode: 0o600 },
  ),
): ChannelTraceSink | undefined {
  if (!/^(1|true|yes)$/i.test(debug.trim())) return undefined;
  if (!path.trim()) throw new Error("AWEB_CHANNEL_DEBUG_FILE is required when channel diagnostics are enabled");

  let reportedFailure = false;
  let pending = mkdir(dirname(path), { recursive: true, mode: 0o700 }).then(() => {});
  return {
    onTrace(entry) {
      const line = `${JSON.stringify(entry)}\n`;
      pending = pending
        .then(() => append(path, line))
        .catch((error) => {
          if (reportedFailure) return;
          reportedFailure = true;
          const detail = error instanceof Error ? error.message : String(error);
          console.error(`aweb: channel trace file unavailable: ${detail}`);
        });
    },
    flush: () => pending,
  };
}

async function main() {
  const workdir = process.cwd();
  const config = await loadChannelConfig(workdir);

  // An external wake path and this channel would both consume the same
  // per-identity event stream, including control signals, so they are mutually
  // exclusive. When delivery is external we stay a healthy but silent MCP
  // server: no claude/channel capability is registered, no stream is opened,
  // and no notification is ever sent. Identity, the bundled aweb skills and the
  // aw CLI are untouched.
  const delivery = resolveChannelDelivery();
  if (delivery.warning) console.error(delivery.warning);
  if (delivery.mode === "session") {
    console.error(CHANNEL_EXTERNAL_DELIVERY_NOTICE);
    const external = createChannelMCPServer({
      capabilities: {},
      instructions: CHANNEL_EXTERNAL_DELIVERY_INSTRUCTIONS,
    });
    await external.connect(new StdioServerTransport());
    return;
  }

  const client = createChannelClient(config);
  // Fail closed: a corrupt/unreadable trust store must abort startup, never
  // silently start with a discarded (empty) store.
  const pinStore = await loadSessionPinStore((message) => {
    console.error(`[aw-channel] fatal: trust pin store unreadable or corrupt: ${message}`);
    process.exit(1);
  });
  if (!pinStore) return;
  const registry = createChannelRegistryResolver(config);
  const trust = new SenderTrustManager(
    client,
    registry,
    config.teamID,
    config.did,
    config.stableID,
  );

  const mcp = createChannelMCPServer(
    {
      capabilities: {
        experimental: { "claude/channel": {} },
      },
      instructions: `Events from the aweb channel are coordination messages from other agents in your team. Use the aw CLI to respond, not MCP tools.

Mail events (type="mail") are async. Mail is marked read when it is presented to you (this notification is that presentation), so you will not be re-notified for the same message. Reply when a reply is warranted: aw mail reply <message_id> --body "<reply>". You do not need to run aw mail ack to prevent redelivery; ack is only a courtesy read-receipt for the sender.

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

  const traceSink = createChannelTraceSink(
    process.env.AWEB_CHANNEL_DEBUG || "",
    process.env.AWEB_CHANNEL_DEBUG_FILE
      || join(workdir, ".aw", `channel-trace-${process.pid}.jsonl`),
  );
  try {
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
      // On Claude the MCP notification IS the presentation of the mail to the
      // agent (Claude presents at the first tool boundary), so mail is marked read
      // at presentation — matching the honest semantic "presented = read". If the
      // transport send fails, the ack is skipped and reconnect re-fetches the still
      // -unread message; if the send succeeds but the process dies before
      // presentation, the message is already read and is reachable only via
      // aw mail show / a read-inclusive view (default-aaka), not by unread-only
      // reconnect. Never acking is not the fix: it left mail unread and caused a
      // replay burst on reconnect (default-aajy).
      mailAcknowledgment: "delivery",
      onTrace: traceSink?.onTrace,
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
  } finally {
    await traceSink?.flush();
  }
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
      // Presented (notification) = read; see startChannelLoop above (aajy).
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
