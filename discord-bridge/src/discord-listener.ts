import type { Client, Message, PartialMessage, ThreadChannel } from "discord.js";
import { MessageFlags } from "discord.js";
import type Redis from "ioredis";
import type { SessionMap } from "./session-map.js";
import type { AiInboxMessage } from "./types.js";
import { joinSession, sendMessage, createOrSendChat } from "./beadhub-client.js";
import { markRelayed } from "./redis-listener.js";
import { config } from "./config.js";

const AI_INBOX = "ai:inbox";

/**
 * Scripty voice transcription bot application ID.
 * Verify against message.applicationId in bridge logs if this changes.
 */
const SCRIPTY_APP_ID = "811652199100317726";

/** Pending voice notes awaiting Scripty transcription: Discord message ID → author info */
interface PendingVoiceNote {
  authorName: string;
  threadId: string;
  timestamp: number;
}
const pendingVoiceNotes = new Map<string, PendingVoiceNote>();

/** Returns true if the message is a Discord voice note (audio-only, no text). */
function isVoiceNote(message: Message): boolean {
  return message.flags.has(MessageFlags.IsVoiceMessage);
}

/** Store a voice note pending Scripty transcription. Prunes entries older than 5 minutes. */
function storePendingVoiceNote(message: Message): void {
  if (!message.channel.isThread()) return;
  const authorName = message.member?.displayName ?? message.author.username;
  pendingVoiceNotes.set(message.id, {
    authorName,
    threadId: message.channel.id,
    timestamp: Date.now(),
  });
  // Prune stale entries (older than 5 minutes)
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [id, entry] of pendingVoiceNotes) {
    if (entry.timestamp < cutoff) pendingVoiceNotes.delete(id);
  }
}

/** Any channel that supports typing indicators */
type TypableChannel = { id: string; sendTyping(): Promise<unknown> };

/** Active typing indicators keyed by channel/thread ID */
const typingIntervals = new Map<string, Timer>();

/** Start a typing indicator loop in a channel or thread. Fires every 8s (indicator lasts ~10s). */
export function startTypingIndicator(channel: TypableChannel): void {
  stopTypingIndicator(channel.id);
  // Fire immediately, then every 8 seconds
  channel.sendTyping().catch(() => {});
  const interval = setInterval(() => {
    channel.sendTyping().catch(() => {});
  }, 8_000);
  typingIntervals.set(channel.id, interval);
}

/** Stop the typing indicator for a channel or thread. */
export function stopTypingIndicator(channelId: string): void {
  const existing = typingIntervals.get(channelId);
  if (existing) {
    clearInterval(existing);
    typingIntervals.delete(channelId);
  }
}

/**
 * Listen for human replies in Discord threads and route them:
 * - New threads (no session) → orchestrator via BeadHub chat API
 * - Existing "beadhub" threads → BeadHub API (original behavior)
 * - Legacy "orchestrator" threads → migrated to BeadHub chat API
 *
 * The orchestrator (ordis) receives messages via the bdh :notify hook,
 * which polls for pending BeadHub chat messages after each tool use.
 *
 * Special handling:
 * - Voice notes (MessageFlags.IsVoiceMessage) are stored pending Scripty transcription
 * - Scripty transcribes by EDITING the original voice note message (not sending a new reply),
 *   so we catch transcriptions via the messageUpdate event.
 */
export function startDiscordListener(
  client: Client,
  sessionMap: SessionMap,
  bridgeIdentity: { workspace_id: string; alias: string },
  redis: Redis,
): void {
  client.on("messageCreate", async (message: Message) => {
    try {
      await handleMessage(message, sessionMap, bridgeIdentity, redis);
    } catch (err) {
      console.error("[discord-listener] Error handling message:", err);
    }
  });

  // Scripty edits the original voice note message with the transcript instead of replying.
  // Detect transcriptions by checking if the updated message ID is in our pending voice notes map.
  client.on("messageUpdate", async (_old: Message | PartialMessage, newMessage: Message | PartialMessage) => {
    console.log(`[discord-listener] messageUpdate fired: id=${newMessage.id} partial=${newMessage.partial} inPending=${pendingVoiceNotes.has(newMessage.id)}`);
    try {
      await handleVoiceNoteEdit(newMessage, sessionMap, bridgeIdentity, redis);
    } catch (err) {
      console.error("[discord-listener] Error handling message update:", err);
    }
  });

  console.log("[discord-listener] Listening for thread replies (BeadHub + orchestrator routing)");
}

async function handleMessage(
  message: Message,
  sessionMap: SessionMap,
  bridgeIdentity: { workspace_id: string; alias: string },
  redis: Redis,
): Promise<void> {
  // Ignore bots (including our own webhook messages)
  if (message.author.bot) return;

  // Ordis channel: flat conversation (no threads) → control-plane chat
  if (
    config.discord.ordisChannelId &&
    message.channel.id === config.discord.ordisChannelId &&
    !message.channel.isThread()
  ) {
    const displayName = message.member?.displayName ?? message.author.username;
    await routeToOrdisChannel(displayName, message.content);
    if ("sendTyping" in message.channel) {
      startTypingIndicator(message.channel as TypableChannel);
    }
    return;
  }

  // Only handle messages in threads
  if (!message.channel.isThread()) return;

  const parentId = message.channel.parentId;

  const isAiChannel = config.discord.aiChannelId && parentId === config.discord.aiChannelId;

  // Only handle threads in our configured channels
  if (!isAiChannel && parentId !== config.discord.channelId) return;

  const threadId = message.channel.id;
  const displayName = message.member?.displayName ?? message.author.username;

  // Drop voice notes — store pending entry so Scripty transcription can be remapped
  if (isVoiceNote(message)) {
    storePendingVoiceNote(message);
    console.log(
      `[discord-listener] Voice note from ${displayName} in thread ${threadId} — awaiting Scripty`,
    );
    return;
  }

  // Route AI channel messages to ai:inbox
  if (isAiChannel) {
    await pushToAiInbox(redis, sessionMap, threadId, displayName, message.content);
    startTypingIndicator(message.channel);
    return;
  }

  // Look up existing session mapping
  const sessionId = await sessionMap.getSessionId(threadId);

  if (!sessionId) {
    // New thread with no session — route to orchestrator via BeadHub chat
    await routeToOrchestratorViaChat(sessionMap, threadId, displayName, message.content, bridgeIdentity);
    startTypingIndicator(message.channel);
    return;
  }

  // Check the source of this session
  const source = await sessionMap.getSource(threadId);

  if (source === "orchestrator") {
    // Legacy orchestrator-managed thread — migrate to BeadHub chat routing
    const result = await sendToOrchestratorChat(displayName, message.content);
    await sessionMap.setWithSource(result.sessionId, threadId, "beadhub");
    startTypingIndicator(message.channel);
    return;
  }

  // Default: BeadHub-managed thread — relay via BeadHub API.
  // If BeadHub returns 404 (session gone), fall back to orchestrator chat routing.
  try {
    await relayToBeadHub(sessionId, displayName, message, bridgeIdentity);
  } catch (err) {
    const is404 = err instanceof Error && err.message.includes("404");
    if (is404) {
      console.log(`[discord-listener] BeadHub session ${sessionId.slice(0, 8)}... gone — routing via orchestrator chat`);
      await routeToOrchestratorViaChat(sessionMap, threadId, displayName, message.content, bridgeIdentity);
      startTypingIndicator(message.channel);
    } else {
      throw err;
    }
  }
}

/**
 * Handle a Scripty transcription delivered via message edit.
 * Scripty edits the original voice note message in-place with the transcript text,
 * rather than sending a new reply. We detect this by checking the updated message ID
 * against our pending voice notes map.
 *
 * Note: SCRIPTY_APP_ID is kept as a reference constant above but is not needed here —
 * the pending map already tells us this was a voice note we're waiting on.
 */
async function handleVoiceNoteEdit(
  rawMessage: Message | PartialMessage,
  sessionMap: SessionMap,
  bridgeIdentity: { workspace_id: string; alias: string },
  redis: Redis,
): Promise<void> {
  // Fetch the full message if we only have a partial
  const message = rawMessage.partial ? await rawMessage.fetch() : rawMessage;

  // Scripty sends its own reply message and edits it with the transcript.
  // Check if this updated message is a reply to a pending voice note.
  const referencedId = message.reference?.messageId;
  const pending = pendingVoiceNotes.get(referencedId ?? "") ?? pendingVoiceNotes.get(message.id);
  if (!pending) return;

  // Guard: must be a thread in one of our configured channels
  if (!message.channel.isThread()) return;
  const editParentId = message.channel.parentId;
  const isAiChannel = config.discord.aiChannelId && editParentId === config.discord.aiChannelId;
  if (!isAiChannel && editParentId !== config.discord.channelId) return;

  const transcript = message.content;
  if (!transcript?.trim()) {
    console.log("[discord-listener] Scripty edit has no text content yet, skipping");
    return;
  }

  // Skip Scripty's intermediate progress messages before the real transcript arrives.
  // Scripty stages: "Downloading file...", "Transcoding file...", "Transcribing file..."
  // Match any "<verb>ing file" pattern to catch all progress stages.
  if (/^\w+ing file/i.test(transcript)) {
    console.log("[discord-listener] Scripty progress message, waiting for real transcript");
    return;
  }

  // Consume the pending entry (keyed by the voice note ID)
  const pendingKey = referencedId && pendingVoiceNotes.has(referencedId) ? referencedId : message.id;
  pendingVoiceNotes.delete(pendingKey);

  // Strip Scripty formatting: remove leading `> ` blockquote lines and trailing `-# ...` metadata
  const cleanTranscript = transcript
    .split("\n")
    .filter((line) => !line.startsWith("-#"))
    .map((line) => (line.startsWith("> ") ? line.slice(2) : line))
    .join(" ")
    .trim();

  const { authorName, threadId } = pending;
  console.log(
    `[discord-listener] Scripty transcription (via edit) for ${authorName}: "${cleanTranscript.slice(0, 80)}"`,
  );

  // Route the transcription as the original human's message
  const thread = message.channel as ThreadChannel;

  // AI channel transcriptions → ai:inbox
  if (isAiChannel) {
    await pushToAiInbox(redis, sessionMap, threadId, authorName, cleanTranscript);
    startTypingIndicator(thread);
    return;
  }

  const sessionId = await sessionMap.getSessionId(threadId);

  if (!sessionId) {
    await routeToOrchestratorViaChat(sessionMap, threadId, authorName, cleanTranscript, bridgeIdentity);
    startTypingIndicator(thread);
    return;
  }

  const source = await sessionMap.getSource(threadId);

  if (source === "orchestrator") {
    // Legacy orchestrator-managed thread — migrate to BeadHub chat routing
    const result = await sendToOrchestratorChat(authorName, cleanTranscript);
    await sessionMap.setWithSource(result.sessionId, threadId, "beadhub");
    startTypingIndicator(thread);
    return;
  }

  // BeadHub-managed thread — fall back to orchestrator chat if session is gone
  try {
    await relayToBeadHub(sessionId, authorName, message, bridgeIdentity, cleanTranscript);
  } catch (err) {
    const is404 = err instanceof Error && err.message.includes("404");
    if (is404) {
      console.log(`[discord-listener] BeadHub session ${sessionId.slice(0, 8)}... gone — routing via orchestrator chat`);
      await routeToOrchestratorViaChat(sessionMap, threadId, authorName, cleanTranscript, bridgeIdentity);
      startTypingIndicator(thread);
    } else {
      throw err;
    }
  }
}

/**
 * Route a new Discord thread message to the orchestrator via BeadHub chat API.
 * Creates a new session and maps it to the Discord thread.
 */
async function routeToOrchestratorViaChat(
  sessionMap: SessionMap,
  threadId: string,
  displayName: string,
  content: string,
  _bridgeIdentity: { workspace_id: string; alias: string },
): Promise<void> {
  const result = await sendToOrchestratorChat(displayName, content);
  await sessionMap.setWithSource(result.sessionId, threadId, "beadhub");
  console.log(
    `[discord->orchestrator] New chat session ${result.sessionId.slice(0, 8)}... for thread ${threadId}`,
  );
}

/**
 * Send a message to the orchestrator via BeadHub aweb chat API.
 * Uses POST /v1/chat/sessions which creates or reuses a session automatically.
 * The bdh :notify hook on the orchestrator side will detect the pending message.
 */
async function sendToOrchestratorChat(
  author: string,
  content: string,
): Promise<{ sessionId: string; messageId: string }> {
  const orchestratorAlias = config.orchestrator.alias;
  const body = `[${author} via Discord] ${content}`;

  const result = await createOrSendChat([orchestratorAlias], body);

  // Mark as relayed so redis-listener doesn't echo it back to Discord
  markRelayed(result.message_id, config.echoSuppressionTtlMs);

  console.log(
    `[discord->orchestrator] ${author} via chat: ${content.slice(0, 80)}`,
  );

  return { sessionId: result.session_id, messageId: result.message_id };
}

/** Push message to ai:inbox Redis list for the AI dispatcher */
async function pushToAiInbox(
  redis: Redis,
  sessionMap: SessionMap,
  threadId: string,
  author: string,
  message: string,
): Promise<void> {
  // Track the thread as AI-sourced (for outbox routing)
  const existingSession = await sessionMap.getSessionId(threadId);
  if (!existingSession) {
    await sessionMap.setWithSource(threadId, threadId, "ai");
  }

  const payload: AiInboxMessage = {
    thread_id: threadId,
    author,
    message,
    timestamp: new Date().toISOString(),
  };

  await redis.rpush(AI_INBOX, JSON.stringify(payload));
  console.log(
    `[discord->ai] ${author} in thread ${threadId}: ${message.slice(0, 80)}`,
  );
}

/**
 * Route a message from the #ordis Discord channel to BeadHub control-plane chat.
 * Uses the control-plane API key so the message lands in ordis's central inbox.
 */
async function routeToOrdisChannel(
  displayName: string,
  content: string,
): Promise<void> {
  const apiKey = config.controlPlane.apiKey;
  if (!apiKey) {
    console.warn("[discord->ordis] CONTROL_PLANE_API_KEY not set — skipping");
    return;
  }

  const body = `[${displayName} via Discord] ${content}`;
  const result = await createOrSendChat(["ordis"], body, apiKey);

  markRelayed(result.message_id, config.echoSuppressionTtlMs);
  console.log(
    `[discord->ordis] ${displayName}: ${content.slice(0, 80)}`,
  );
}

/** Relay message to BeadHub API (original behavior) */
async function relayToBeadHub(
  sessionId: string,
  displayName: string,
  message: Message,
  bridgeIdentity: { workspace_id: string; alias: string },
  contentOverride?: string,
): Promise<void> {
  // Join the session if we haven't already (idempotent)
  await joinSession(
    sessionId,
    bridgeIdentity.workspace_id,
    bridgeIdentity.alias,
  );

  const content = contentOverride ?? message.content;
  // Format: include the Discord username so agents know who's speaking
  const body = `[${displayName} via Discord] ${content}`;

  // Send to BeadHub
  const messageId = await sendMessage(
    sessionId,
    body,
    bridgeIdentity.workspace_id,
    bridgeIdentity.alias,
  );

  // Mark as relayed so we don't echo it back to Discord
  markRelayed(messageId, config.echoSuppressionTtlMs);

  console.log(
    `[discord->beadhub] ${displayName} in thread ${message.channel.isThread() ? message.channel.name : "?"}: ${content.slice(0, 80)}`,
  );
}
