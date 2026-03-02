import type Redis from "ioredis";
import type { TextChannel, ThreadChannel, WebhookClient } from "discord.js";
import type { BeadHubEvent, ChatMessageEvent } from "./types.js";
import type { SessionMap } from "./session-map.js";
import { config } from "./config.js";
import { getSessionMessages, getProjectRepos } from "./beadhub-client.js";
import { getOrCreateThread, sendAsAgent } from "./discord-sender.js";
import { stopTypingIndicator } from "./discord-listener.js";

/** Set of message_ids we've already relayed (echo suppression + dedup). */
const recentlyRelayed = new Set<string>();

export function markRelayed(messageId: string, ttlMs: number): void {
  recentlyRelayed.add(messageId);
  setTimeout(() => recentlyRelayed.delete(messageId), ttlMs);
}

export function wasRelayed(messageId: string): boolean {
  return recentlyRelayed.has(messageId);
}

/**
 * Subscribe to all workspace event channels via PSUBSCRIBE events:*
 * and relay chat.message_sent events to Discord.
 *
 * The `cmdRedis` client is used for regular commands (RPUSH to orchestrator inbox).
 * A duplicate is created internally for PSUBSCRIBE.
 */
/** Optional ordis webhook for posting to #ordis channel directly */
export interface OrdisWebhookConfig {
  webhookUrl: string;
  controlPlaneProjectId: string;
}

let ordisWebhookConfig: OrdisWebhookConfig | null = null;

export function setOrdisWebhookConfig(cfg: OrdisWebhookConfig): void {
  ordisWebhookConfig = cfg;
}

export async function startRedisListener(
  cmdRedis: Redis,
  channel: TextChannel,
  webhook: WebhookClient,
  sessionMap: SessionMap,
  echoTtlMs: number,
  bridgeAlias: string,
): Promise<void> {
  // ioredis requires a duplicate client for subscriptions
  const sub = cmdRedis.duplicate();

  sub.on("error", (err) => {
    console.error("[redis] Subscription error:", err.message);
  });

  await sub.psubscribe("events:*");
  console.log("[redis] PSUBSCRIBE events:* — listening for chat events");

  sub.on("pmessage", async (_pattern: string, _chan: string, message: string) => {
    try {
      const event: BeadHubEvent = JSON.parse(message);
      if (event.type !== "chat.message_sent") return;

      const chatEvent = event as unknown as ChatMessageEvent;

      // Skip messages sent by the bridge itself (human Discord replies relayed to BeadHub)
      if (chatEvent.from_alias === bridgeAlias) return;

      await handleChatMessage(chatEvent, cmdRedis, channel, webhook, sessionMap, echoTtlMs);
    } catch (err) {
      console.error("[redis] Error handling event:", err);
    }
  });
}

async function handleChatMessage(
  event: ChatMessageEvent,
  cmdRedis: Redis,
  channel: TextChannel,
  webhook: WebhookClient,
  sessionMap: SessionMap,
  echoTtlMs: number,
): Promise<void> {
  // Dedup: same chat message fires on each participant's channel
  if (wasRelayed(event.message_id)) return;
  markRelayed(event.message_id, echoTtlMs);

  // Fetch full message body (event.preview is truncated to 80 chars)
  // Use event.project_id so cross-project sessions resolve correctly.
  const messages = await getSessionMessages(event.session_id, 1, event.project_id || undefined);
  const latest = messages.at(-1);
  if (!latest) {
    console.warn(`[bridge] No messages found for session ${event.session_id}`);
    return;
  }

  let fromAlias: string;
  let body: string;

  // Double-check this is the message we expect
  if (latest.message_id !== event.message_id) {
    // Race condition: Redis event can fire before DB transaction commits.
    // Wait briefly, then retry with more messages.
    await new Promise((r) => setTimeout(r, 500));
    const all = await getSessionMessages(event.session_id, 20, event.project_id || undefined);
    const target = all.find((m) => m.message_id === event.message_id);
    if (!target) {
      // One more retry after a longer delay
      await new Promise((r) => setTimeout(r, 1500));
      const retry = await getSessionMessages(event.session_id, 20, event.project_id || undefined);
      const found = retry.find((m) => m.message_id === event.message_id);
      if (!found) {
        console.warn(`[bridge] Could not find message ${event.message_id} after retries`);
        return;
      }
      fromAlias = found.from_agent;
      body = found.body;
    } else {
      fromAlias = target.from_agent;
      body = target.body;
    }
  } else {
    fromAlias = latest.from_agent;
    body = latest.body;
  }

  // Control-plane messages from ordis → post to #ordis channel directly (no threads)
  if (
    ordisWebhookConfig &&
    event.project_id === ordisWebhookConfig.controlPlaneProjectId
  ) {
    await postToOrdisChannel(fromAlias, body);
    return;
  }

  const thread = await relayToDiscord(fromAlias, body, event, channel, webhook, sessionMap);

  // Route to orchestrator inbox if the chat targets the orchestrator
  await maybeRouteToOrchestrator(event, fromAlias, body, thread, cmdRedis);
}

/** Agent alias → emoji prefix for ordis channel posts */
const AGENT_EMOJIS: Record<string, string> = {
  ordis: "🎯",
  neo: "🔧",
  hawk: "🦅",
};

/**
 * Post a message to the #ordis Discord channel via webhook.
 * Used for control-plane project messages — flat conversation, no threads.
 */
async function postToOrdisChannel(fromAlias: string, body: string): Promise<void> {
  if (!ordisWebhookConfig) return;

  const emoji = AGENT_EMOJIS[fromAlias] ?? "🤖";
  const username = `${emoji} ${fromAlias}`;

  // Split long messages for Discord's 2000-char limit
  const chunks = splitMessage(body, config.maxDiscordMessageLength);
  for (const chunk of chunks) {
    await fetch(ordisWebhookConfig.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, content: chunk }),
    });
  }

  // Stop typing indicator on the ordis channel
  if (config.discord.ordisChannelId) {
    stopTypingIndicator(config.discord.ordisChannelId);
  }

  console.log(`[bridge->ordis] ${fromAlias}: ${body.slice(0, 80)}`);
}

function splitMessage(text: string, maxLen: number): string[] {
  if (text.length <= maxLen) return [text];
  const chunks: string[] = [];
  let remaining = text;
  while (remaining.length > 0) {
    if (remaining.length <= maxLen) {
      chunks.push(remaining);
      break;
    }
    let splitAt = remaining.lastIndexOf("\n", maxLen);
    if (splitAt <= 0) splitAt = maxLen;
    chunks.push(remaining.slice(0, splitAt));
    remaining = remaining.slice(splitAt).replace(/^\n/, "");
  }
  return chunks;
}

async function relayToDiscord(
  fromAlias: string,
  body: string,
  event: ChatMessageEvent,
  channel: TextChannel,
  webhook: WebhookClient,
  sessionMap: SessionMap,
): Promise<ThreadChannel> {
  // Build participant list: sender + recipients
  const participants = [event.from_alias, ...event.to_aliases];
  const uniqueParticipants = [...new Set(participants)];

  const thread = await getOrCreateThread(
    channel,
    sessionMap,
    event.session_id,
    uniqueParticipants,
  );

  await sendAsAgent(webhook, thread, fromAlias, body);
  console.log(
    `[bridge] ${fromAlias} → thread "${thread.name}": ${body.slice(0, 80)}...`,
  );

  return thread;
}

/**
 * If the chat message targets the orchestrator, push it to `orchestrator:inbox`
 * so the dispatcher can wake up and handle it via `processChatMessage()`.
 */
async function maybeRouteToOrchestrator(
  event: ChatMessageEvent,
  fromAlias: string,
  body: string,
  thread: ThreadChannel,
  cmdRedis: Redis,
): Promise<void> {
  const orchestratorAlias = config.orchestrator.alias;

  // Don't relay the orchestrator's own responses back to itself
  if (fromAlias === orchestratorAlias) return;

  // Only route if the orchestrator is one of the recipients
  if (!event.to_aliases.includes(orchestratorAlias)) return;

  // Look up repo origin for the project
  let repoOrigin = "";
  try {
    const repos = await getProjectRepos(event.project_id);
    if (repos.length > 0) {
      repoOrigin = repos[0].canonical_origin;
    }
  } catch (err) {
    console.warn(`[bridge] Failed to fetch repos for project ${event.project_id}:`, err);
  }

  const inboxMessage = {
    type: "bdh_chat",
    thread_id: thread.id,
    from_alias: fromAlias,
    message: body,
    project_slug: event.project_slug ?? "",
    project_id: event.project_id,
    repo_origin: repoOrigin,
    chat_session_id: event.session_id,
    timestamp: event.timestamp,
  };

  await cmdRedis.rpush("orchestrator:inbox", JSON.stringify(inboxMessage));
  console.log(
    `[bridge] Routed bdh chat from ${fromAlias} to orchestrator:inbox (project: ${event.project_slug})`,
  );
}
