#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { resolveConfig } from "./config.js";
import { APIClient } from "./api/client.js";
import { streamAgentEvents, type AgentEvent } from "./api/events.js";
import { fetchInbox } from "./api/mail.js";
import { fetchHistory } from "./api/chat.js";
import { loadSigningKey } from "./identity/keys.js";
import { TOOL_DEFINITIONS, handleToolCall } from "./tools.js";

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
    return handleToolCall(
      req.params.name,
      req.params.arguments as Record<string, unknown>,
      client,
      signing,
    );
  });

  // Connect MCP over stdio
  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  // Start SSE event loop in background
  const abort = new AbortController();
  process.on("SIGINT", () => abort.abort());
  process.on("SIGTERM", () => abort.abort());

  startEventLoop(mcp, client, config.alias, abort.signal);
}

async function startEventLoop(
  mcp: Server,
  client: APIClient,
  selfAlias: string,
  signal: AbortSignal,
): Promise<void> {
  for await (const event of streamAgentEvents(client, signal)) {
    try {
      await dispatchEvent(mcp, client, selfAlias, event);
    } catch (err) {
      console.error(`[aw-channel] dispatch error: ${err}`);
    }
  }
}

async function dispatchEvent(
  mcp: Server,
  client: APIClient,
  selfAlias: string,
  event: AgentEvent,
): Promise<void> {
  switch (event.type) {
    case "mail_message": {
      const messages = await fetchInbox(client, true, 10);
      for (const msg of messages) {
        const meta: Record<string, string> = {
          type: "mail",
          from: msg.from_alias || msg.from_address || "",
          message_id: msg.message_id,
        };
        if (msg.subject) meta.subject = msg.subject;
        if (msg.priority && msg.priority !== "normal") meta.priority = msg.priority;
        if (msg.verification_status) meta.verified = String(msg.verification_status === "verified");

        await mcp.notification({
          method: "notifications/claude/channel",
          params: { content: msg.body, meta },
        });
      }
      break;
    }

    case "chat_message": {
      if (!event.session_id) break;
      const messages = await fetchHistory(client, event.session_id, true, 10);
      for (const msg of messages) {
        // Skip own messages
        if (msg.from_agent === selfAlias) continue;

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
      }
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

    // Coordination events — surface as informational
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

    default:
      break;
  }
}

main().catch((err) => {
  console.error(`[aw-channel] fatal: ${err}`);
  process.exit(1);
});
