#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { join } from "node:path";
import { homedir } from "node:os";
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

import { resolveConfig } from "./config.js";
import { APIClient } from "./api/client.js";
import { streamAgentEvents, type AgentEvent } from "./api/events.js";
import { fetchInbox, ackMessage, type InboxMessage } from "./api/mail.js";
import { fetchHistory, markRead, type ChatMessage } from "./api/chat.js";
import { PinStore } from "./identity/pinstore.js";
import { RegistryResolver } from "./identity/registry.js";
import { SenderTrustManager } from "./identity/trust.js";

const PIN_STORE_PATH = join(homedir(), ".config", "aw", "known_agents.yaml");
const MAX_DISPATCHED_IDS = 2000;
const MAIL_FETCH_LIMIT = 200;
const CHAT_FETCH_LIMIT = 2000;

interface SelfIdentity {
  alias: string;
  address: string;
  did: string;
  stableID: string;
}

async function loadPinStore(): Promise<PinStore> {
  try {
    const content = await readFile(PIN_STORE_PATH, "utf-8");
    return PinStore.fromYAML(content);
  } catch {
    return new PinStore();
  }
}

function pruneDispatched(dispatched: Set<string>): void {
  if (dispatched.size <= MAX_DISPATCHED_IDS) return;
  const excess = dispatched.size - MAX_DISPATCHED_IDS;
  let removed = 0;
  for (const id of dispatched) {
    if (removed >= excess) break;
    dispatched.delete(id);
    removed++;
  }
}

async function main() {
  const workdir = process.cwd();
  const config = await resolveConfig(workdir);

  const client = new APIClient(config.baseURL, {
    did: config.did,
    stableID: config.stableID,
    signingKey: config.signingKey,
    teamID: config.teamID,
    teamCertificateHeader: config.teamCertificateHeader,
  });
  const pinStore = await loadPinStore();
  const registry = new RegistryResolver(fetch, undefined, undefined, {
    fallbackRegistryURL: resolveRegistryFallbackURL(config.baseURL, config.registryURL),
  });
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

Mail events (type="mail") are async. Read them and act if needed. Delivery through this channel already acknowledges receipt, so there is no separate ack command.

Chat events (type="chat") may have sender_waiting="true", meaning the sender is blocked waiting for your reply. Respond promptly with: aw chat send-and-wait <from> "<reply>"
If you need more time, send a status update the same way.

Control events (type="control") are operational signals. On "pause", stop current work and wait. On "resume", continue. On "interrupt", stop and await new instructions.`,
    },
  );

  // Connect MCP over stdio
  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  // Start SSE event loop in background
  const abort = new AbortController();
  process.on("SIGINT", () => abort.abort());
  process.on("SIGTERM", () => abort.abort());

  await startEventLoop(
    mcp,
    client,
    pinStore,
    trust,
    {
      alias: config.alias,
      address: config.address,
      did: config.did,
      stableID: config.stableID,
    },
    abort.signal,
  );
}

export function resolveRegistryFallbackURL(baseURL: string, identityRegistryURL: string = ""): string | undefined {
  const envRegistryURL = (process.env.AWID_REGISTRY_URL || "").trim();
  if (envRegistryURL) {
    return envRegistryURL.toLowerCase() === "local" ? baseURL : envRegistryURL;
  }
  const configuredRegistryURL = identityRegistryURL.trim();
  return configuredRegistryURL || undefined;
}

async function startEventLoop(
  mcp: Server,
  client: APIClient,
  pinStore: PinStore,
  trust: SenderTrustManager,
  self: SelfIdentity,
  signal: AbortSignal,
): Promise<void> {
  const dispatched = new Set<string>();

  for await (const event of streamAgentEvents(client, signal)) {
    try {
      await dispatchEvent(mcp, client, pinStore, trust, self, dispatched, event);
      pruneDispatched(dispatched);
    } catch (err) {
      console.error(`[aw-channel] dispatch error: ${err}`);
    }
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
): Promise<void> {
  switch (event.type) {
    case "mail_message": {
      const messages = await fetchInbox(client, true, MAIL_FETCH_LIMIT, event.message_id);
      let pinsDirty = false;
      for (const msg of messages) {
        if (isSelfSender(msg.from_alias, msg.from_address, msg.from_stable_id, msg.from_did, self)) continue;
        if (dispatched.has(msg.message_id)) continue;
        dispatched.add(msg.message_id);

        const from = senderDisplayAddress(msg.from_alias, msg.from_address);
        const tofu = await trust.normalizeTrust(
          pinStore,
          msg.verification_status,
          senderTrustAddress(msg.from_alias, msg.from_address),
          msg.from_did,
          msg.from_stable_id,
          msg.to_did,
          msg.to_stable_id,
          msg.rotation_announcement,
          msg.replacement_announcement,
          msg.from_address || msg.from_alias || "",
        );
        msg.verification_status = tofu.status as InboxMessage["verification_status"];
        if (tofu.stored) pinsDirty = true;

        const meta: Record<string, string> = {
          type: "mail",
          from,
          message_id: msg.message_id,
        };
        if (msg.subject) meta.subject = msg.subject;
        if (msg.priority && msg.priority !== "normal") meta.priority = msg.priority;
        if (msg.verification_status) meta.verified = String(msg.verification_status === "verified" || msg.verification_status === "verified_custodial");

        await mcp.notification({
          method: "notifications/claude/channel",
          params: { content: msg.body, meta },
        });

        // Auto-ack: message has been delivered to Claude
        ackMessage(client, msg.message_id).catch((err) =>
          console.error(`[aw-channel] ack failed: ${err}`),
        );
      }
      if (pinsDirty) await pinStore.save(PIN_STORE_PATH);
      break;
    }

    case "chat_message": {
      if (!event.session_id) break;
      const messages = await fetchHistory(client, event.session_id, true, CHAT_FETCH_LIMIT, event.message_id);
      let pinsDirty = false;
      let lastMessageId: string | undefined;
      for (const msg of messages) {
        if (isSelfSender(msg.from_agent, msg.from_address, msg.from_stable_id, msg.from_did, self)) continue;
        if (dispatched.has(msg.message_id)) continue;
        dispatched.add(msg.message_id);

        const from = senderDisplayAddress(msg.from_agent, msg.from_address);
        const tofu = await trust.normalizeTrust(
          pinStore,
          msg.verification_status,
          senderTrustAddress(msg.from_agent, msg.from_address),
          msg.from_did,
          msg.from_stable_id,
          msg.to_did,
          msg.to_stable_id,
          msg.rotation_announcement,
          msg.replacement_announcement,
          msg.from_address || msg.from_agent || "",
        );
        msg.verification_status = tofu.status as ChatMessage["verification_status"];
        if (tofu.stored) pinsDirty = true;

        const meta: Record<string, string> = {
          type: "chat",
          from,
          session_id: event.session_id,
          message_id: msg.message_id,
        };
        if (event.sender_waiting) meta.sender_waiting = "true";
        if (msg.sender_leaving) meta.sender_leaving = "true";
        if (msg.verification_status) meta.verified = String(msg.verification_status === "verified" || msg.verification_status === "verified_custodial");

        await mcp.notification({
          method: "notifications/claude/channel",
          params: { content: msg.body, meta },
        });

        lastMessageId = msg.message_id;
      }

      // Mark read up to last dispatched message
      if (lastMessageId) {
        markRead(client, event.session_id, lastMessageId).catch((err) =>
          console.error(`[aw-channel] mark-read failed: ${err}`),
        );
      }

      if (pinsDirty) await pinStore.save(PIN_STORE_PATH);
      break;
    }

    case "control_pause":
    case "control_resume":
    case "control_interrupt": {
      const signalType = event.type.replace("control_", "");
      await mcp.notification({
        method: "notifications/claude/channel",
        params: {
          content: "",
          meta: {
            type: "control",
            signal: signalType,
            signal_id: event.signal_id || "",
          },
        },
      });
      break;
    }

    case "work_available": {
      await mcp.notification({
        method: "notifications/claude/channel",
        params: {
          content: event.title || "",
          meta: {
            type: "work",
            task_id: event.task_id || "",
          },
        },
      });
      break;
    }

    case "claim_update": {
      await mcp.notification({
        method: "notifications/claude/channel",
        params: {
          content: event.title || "",
          meta: {
            type: "claim",
            task_id: event.task_id || "",
            title: event.title || "",
            status: event.status || "",
          },
        },
      });
      break;
    }

    case "claim_removed": {
      await mcp.notification({
        method: "notifications/claude/channel",
        params: {
          content: "",
          meta: {
            type: "claim_removed",
            task_id: event.task_id || "",
          },
        },
      });
      break;
    }

    default:
      break;
  }
}

function senderDisplayAddress(alias: string | undefined, address: string | undefined): string {
  const qualified = (address || "").trim();
  if (qualified) return qualified;
  return (alias || "").trim();
}

function senderTrustAddress(alias: string | undefined, address: string | undefined): string {
  const qualified = (address || "").trim();
  if (qualified) return qualified;
  return (alias || "").trim();
}

function isSelfSender(
  alias: string | undefined,
  address: string | undefined,
  stableID: string | undefined,
  did: string | undefined,
  self: SelfIdentity,
): boolean {
  const msgAddress = (address || "").trim();
  const msgStableID = (stableID || "").trim();
  const msgDID = (did || "").trim();
  const selfAddress = self.address.trim();
  const selfStableID = self.stableID.trim();
  const selfDID = self.did.trim();

  if (selfAddress && msgAddress && selfAddress === msgAddress) return true;
  if (selfStableID && (msgStableID === selfStableID || msgDID === selfStableID)) return true;
  if (selfDID && (msgStableID === selfDID || msgDID === selfDID)) return true;

  if ((selfAddress || selfStableID || selfDID) && (msgAddress || msgStableID || msgDID)) {
    return false;
  }

  const selfAlias = self.alias.trim();
  if (!selfAlias) return false;
  return (alias || "").trim() === selfAlias;
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
