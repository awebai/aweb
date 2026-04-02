#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { join } from "node:path";
import { homedir } from "node:os";
import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { resolveConfig } from "./config.js";
import { APIClient } from "./api/client.js";
import { streamAgentEvents, type AgentEvent } from "./api/events.js";
import { fetchInbox, ackMessage, type InboxMessage } from "./api/mail.js";
import { fetchHistory, markRead, type ChatMessage } from "./api/chat.js";
import { loadSigningKey } from "./identity/keys.js";
import { PinStore } from "./identity/pinstore.js";
import { TOOL_DEFINITIONS, handleToolCall } from "./tools.js";

const PIN_STORE_PATH = join(homedir(), ".config", "aw", "known_agents.yaml");
const MAX_DISPATCHED_IDS = 2000;

async function loadPinStore(): Promise<PinStore> {
  try {
    const content = await readFile(PIN_STORE_PATH, "utf-8");
    return PinStore.fromYAML(content);
  } catch {
    return new PinStore();
  }
}

async function savePinStore(store: PinStore): Promise<void> {
  await writeFile(PIN_STORE_PATH, store.toYAML(), { mode: 0o600 });
}

interface TOFUResult {
  status: string | undefined;
  stored: boolean;
}

function checkTOFUPin(
  store: PinStore,
  verificationStatus: string | undefined,
  fromAlias: string,
  fromDID: string | undefined,
  fromStableID: string | undefined,
): TOFUResult {
  if (!verificationStatus || verificationStatus !== "verified" || !fromDID || !fromAlias) {
    return { status: verificationStatus, stored: false };
  }

  const pinKey = fromStableID?.startsWith("did:aw:") ? fromStableID : fromDID;
  const result = store.checkPin(fromAlias, pinKey, "persistent");

  switch (result) {
    case "new":
      store.storePin(pinKey, fromAlias, "", "");
      if (fromStableID?.startsWith("did:aw:")) {
        const pin = store.pins.get(pinKey)!;
        pin.stable_id = fromStableID;
        pin.did_key = fromDID;
      }
      return { status: verificationStatus, stored: true };
    case "ok":
      return { status: verificationStatus, stored: false };
    case "mismatch":
      return { status: "identity_mismatch", stored: false };
    case "skipped":
      return { status: verificationStatus, stored: false };
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

  // Load signing key if available
  let seed: Uint8Array | null = null;
  if (config.signingKeyPath) {
    try {
      seed = await loadSigningKey(config.signingKeyPath);
    } catch (err) {
      console.error(`[aw-channel] failed to load signing key: ${err}`);
    }
  }

  const client = new APIClient(config.baseURL, config.apiKey);
  const pinStore = await loadPinStore();
  const signing = {
    seed,
    did: config.did,
    stableID: config.stableID,
    alias: config.alias,
    projectSlug: config.projectSlug,
  };

  const mcp = new Server(
    { name: "aw", version: "0.0.1" },
    {
      capabilities: {
        experimental: { "claude/channel": {} },
        tools: {},
      },
      instructions: `Events from the aw channel are coordination messages from other agents in your team.

Mail events (type="mail") are async, fire-and-forget. Read them, act if needed, acknowledge with mail_ack.

Chat events (type="chat") may have sender_waiting="true", meaning the sender is blocked waiting for your reply. Respond promptly with chat_reply using the session_id from the event. If you need more time, send a chat_reply with a status update.

Control events (type="control") are operational signals. On "pause", stop current work and wait. On "resume", continue. On "interrupt", stop and await new instructions.

Always use the session_id and message_id from the event attributes when replying or acknowledging.`,
    },
  );

  // Register tool handlers
  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS,
  }));

  mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
    try {
      return await handleToolCall(
        req.params.name,
        req.params.arguments as Record<string, unknown>,
        client,
        signing,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: `error: ${msg}` }], isError: true };
    }
  });

  // Connect MCP over stdio
  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  // Start SSE event loop in background
  const abort = new AbortController();
  process.on("SIGINT", () => abort.abort());
  process.on("SIGTERM", () => abort.abort());

  startEventLoop(mcp, client, pinStore, config.alias, abort.signal);
}

async function startEventLoop(
  mcp: Server,
  client: APIClient,
  pinStore: PinStore,
  selfAlias: string,
  signal: AbortSignal,
): Promise<void> {
  const dispatched = new Set<string>();

  for await (const event of streamAgentEvents(client, signal)) {
    try {
      await dispatchEvent(mcp, client, pinStore, selfAlias, dispatched, event);
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
  selfAlias: string,
  dispatched: Set<string>,
  event: AgentEvent,
): Promise<void> {
  switch (event.type) {
    case "mail_message": {
      const messages = await fetchInbox(client, true, 10);
      let pinsDirty = false;
      for (const msg of messages) {
        if (dispatched.has(msg.message_id)) continue;
        dispatched.add(msg.message_id);

        const from = msg.from_alias || msg.from_address || "";
        const tofu = checkTOFUPin(
          pinStore, msg.verification_status, from, msg.from_did, msg.from_stable_id,
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
        if (msg.verification_status) meta.verified = String(msg.verification_status === "verified");

        await mcp.notification({
          method: "notifications/claude/channel",
          params: { content: msg.body, meta },
        });

        // Auto-ack: message has been delivered to Claude
        ackMessage(client, msg.message_id).catch((err) =>
          console.error(`[aw-channel] ack failed: ${err}`),
        );
      }
      if (pinsDirty) await savePinStore(pinStore);
      break;
    }

    case "chat_message": {
      if (!event.session_id) break;
      const messages = await fetchHistory(client, event.session_id, true, 10);
      let pinsDirty = false;
      let lastMessageId: string | undefined;
      for (const msg of messages) {
        if (msg.from_agent === selfAlias) continue;
        if (dispatched.has(msg.message_id)) continue;
        dispatched.add(msg.message_id);

        const tofu = checkTOFUPin(
          pinStore, msg.verification_status, msg.from_agent, msg.from_did, msg.from_stable_id,
        );
        msg.verification_status = tofu.status as ChatMessage["verification_status"];
        if (tofu.stored) pinsDirty = true;

        const meta: Record<string, string> = {
          type: "chat",
          from: msg.from_agent,
          session_id: event.session_id,
          message_id: msg.message_id,
        };
        if (msg.sender_leaving) meta.sender_leaving = "true";
        if (msg.verification_status) meta.verified = String(msg.verification_status === "verified");

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

      if (pinsDirty) await savePinStore(pinStore);
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

function isDirectExecution(moduleURL: string): boolean {
  const entry = process.argv[1];
  return !!entry && moduleURL === pathToFileURL(entry).href;
}

if (isDirectExecution(import.meta.url)) {
  main().catch((err) => {
    console.error(`[aw-channel] fatal: ${err}`);
    process.exit(1);
  });
}
