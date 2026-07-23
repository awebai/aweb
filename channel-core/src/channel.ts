import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { mkdir, readFile, writeFile } from "node:fs/promises";

import { APIClient } from "./api/client.js";
import { streamAgentEvents, type AgentEvent, type EventStreamState } from "./api/events.js";
import { ackMessage, fetchInbox, type InboxMessage } from "./api/mail.js";
import { fetchHistory, markRead, type ChatMessage } from "./api/chat.js";
import { PinStore } from "./identity/pinstore.js";
import { RegistryResolver } from "./identity/registry.js";
import { SenderTrustManager } from "./identity/trust.js";
import type { VerificationStatus } from "./identity/signing.js";
import { createLocalAWDecryptProvider, type LocalDecryptProvider } from "./local_aw.js";

export const DEFAULT_PIN_STORE_PATH = join(homedir(), ".config", "aw", "known_agents.yaml");
export const DEFAULT_DELIVERY_STORE_PATH = join(homedir(), ".config", "aw", "channel-delivered-ids.json");
const MAX_DISPATCHED_IDS = 2000;
const MAX_DELIVERED_IDS = 5000;
const DELIVERED_IDS_TTL_MS = 24 * 60 * 60 * 1000;
const MAIL_FETCH_LIMIT = 200;
const CHAT_FETCH_LIMIT = 2000;
const APP_EVENT_SUMMARY_SEPARATOR = " — ";
const MAX_APP_EVENT_VALUE_LENGTH = 160;
const MAX_APP_EVENT_PAYLOAD_LENGTH = 500;

export interface SelfIdentity {
  alias: string;
  address: string;
  did: string;
  stableID: string;
}

export type ChannelAwakeningKind = "mail" | "chat" | "control" | "work" | "claim" | "claim_removed" | "app";
export type ChannelDeliveryIntent = "wake" | "steer" | "ambient";

export interface ChannelAwakening {
  kind: ChannelAwakeningKind;
  content: string;
  meta: Record<string, string>;
  deliveryIntent: ChannelDeliveryIntent;
}

export interface ChannelLoopOptions {
  client: APIClient;
  pinStore: PinStore;
  pinStorePath?: string;
  trust: SenderTrustManager;
  self: SelfIdentity;
  signal: AbortSignal;
  onAwakening: (awakening: ChannelAwakening) => Promise<void> | void;
  mailAcknowledgment?: "delivery" | "manual";
  deliveryStore?: DeliveryStore;
  localDecrypt?: LocalDecryptProvider;
  workdir?: string;
  awCommand?: string;
  log?: (message: string) => void;
  onStreamState?: (state: EventStreamState) => void;
}

export async function loadPinStore(path: string = DEFAULT_PIN_STORE_PATH): Promise<PinStore> {
  try {
    const content = await readFile(path, "utf-8");
    return PinStore.fromYAML(content);
  } catch {
    return new PinStore();
  }
}

export class DeliveryStore {
  private constructor(
    private readonly path: string,
    private entries: Map<string, number>,
  ) {}

  static async load(path: string = DEFAULT_DELIVERY_STORE_PATH): Promise<DeliveryStore> {
    try {
      const raw = JSON.parse(await readFile(path, "utf-8")) as Record<string, string | number>;
      const now = Date.now();
      const entries = new Map<string, number>();
      for (const [key, value] of Object.entries(raw)) {
        const timestamp = typeof value === "number" ? value : Date.parse(value);
        if (Number.isFinite(timestamp) && now - timestamp <= DELIVERED_IDS_TTL_MS) {
          entries.set(key, timestamp);
        }
      }
      return new DeliveryStore(path, entries);
    } catch {
      return new DeliveryStore(path, new Map());
    }
  }

  has(key: string): boolean {
    this.prune();
    return this.entries.has(key);
  }

  mark(key: string): void {
    this.entries.set(key, Date.now());
    this.prune();
  }

  async save(): Promise<void> {
    this.prune();
    await mkdir(dirname(this.path), { recursive: true });
    const payload = Object.fromEntries(
      [...this.entries.entries()].map(([key, value]) => [key, new Date(value).toISOString()]),
    );
    await writeFile(this.path, `${JSON.stringify(payload, null, 2)}\n`, "utf-8");
  }

  private prune(): void {
    const now = Date.now();
    for (const [key, value] of this.entries) {
      if (now - value > DELIVERED_IDS_TTL_MS) this.entries.delete(key);
    }
    if (this.entries.size <= MAX_DELIVERED_IDS) return;
    const sorted = [...this.entries.entries()].sort((a, b) => a[1] - b[1]);
    for (const [key] of sorted.slice(0, this.entries.size - MAX_DELIVERED_IDS)) {
      this.entries.delete(key);
    }
  }
}

export function resolveRegistryFallbackURL(identityRegistryURL: string = ""): string | undefined {
  const envRegistryURL = (process.env.AWID_REGISTRY_URL || "").trim();
  if (envRegistryURL) {
    if (envRegistryURL.toLowerCase() === "local") {
      throw new Error("AWID_REGISTRY_URL=local is not supported; set AWID_REGISTRY_URL=https://api.awid.ai");
    }
    return envRegistryURL;
  }
  const configuredRegistryURL = identityRegistryURL.trim();
  return configuredRegistryURL || undefined;
}

export function createRegistryResolver(registryURL: string = ""): RegistryResolver {
  return new RegistryResolver(fetch, undefined, undefined, {
    fallbackRegistryURL: resolveRegistryFallbackURL(registryURL),
  });
}

export function createChannelClient(config: {
  baseURL: string;
  did: string;
  stableID: string;
  signingKey: Uint8Array;
  teamID: string;
  teamCertificateHeader: string;
}): APIClient {
  return new APIClient(config.baseURL, {
    did: config.did,
    stableID: config.stableID,
    signingKey: config.signingKey,
    teamID: config.teamID,
    teamCertificateHeader: config.teamCertificateHeader,
  });
}

export async function startChannelLoop(options: ChannelLoopOptions): Promise<void> {
  const dispatched = new Set<string>();
  const deliveryStore = options.deliveryStore || await DeliveryStore.load(DEFAULT_DELIVERY_STORE_PATH);
  const localDecrypt = options.localDecrypt || (
    options.workdir ? createLocalAWDecryptProvider({ workdir: options.workdir, awCommand: options.awCommand }) : undefined
  );
  await consumeAgentEvents(
    { ...options, deliveryStore, localDecrypt },
    dispatched,
    streamAgentEvents(options.client, options.signal, options.onStreamState),
    options.log || (() => {}),
  );
}

export async function consumeAgentEvents(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  events: AsyncIterable<AgentEvent>,
  log: (message: string) => void = () => {},
): Promise<void> {
  const lanes = new Map<string, Promise<void>>();
  const pending = new Set<Promise<void>>();

  for await (const event of events) {
    const lane = eventDispatchLane(event);
    const previous = lane ? lanes.get(lane) : undefined;
    const job = (previous || Promise.resolve())
      .then(async () => {
        await dispatchAgentEvent(options, dispatched, event);
        pruneDispatched(dispatched);
      })
      .catch(() => {
        log("aweb: could not process an incoming event; it remains pending");
      });
    pending.add(job);
    if (lane) lanes.set(lane, job);
    void job.finally(() => {
      pending.delete(job);
      if (lane && lanes.get(lane) === job) lanes.delete(lane);
    });
  }

  await Promise.all([...pending]);
}

function eventDispatchLane(event: AgentEvent): string {
  switch (event.type) {
    case "mail_message":
      return "mail";
    case "chat_message":
      return `chat:${event.session_id || event.conversation_id || "unknown"}`;
    default:
      return "";
  }
}

export async function dispatchAgentEvent(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  event: AgentEvent,
): Promise<void> {
  switch (event.type) {
    case "mail_message":
      await dispatchMailEvent(options, dispatched, event);
      break;
    case "chat_message":
      await dispatchChatEvent(options, dispatched, event);
      break;
    case "control_pause":
    case "control_resume":
    case "control_interrupt":
      await options.onAwakening({
        kind: "control",
        content: "",
        deliveryIntent: "steer",
        meta: {
          type: "control",
          signal: event.type.replace("control_", ""),
          signal_id: event.signal_id || "",
        },
      });
      break;
    case "work_available":
      await options.onAwakening({
        kind: "work",
        content: event.title || "",
        deliveryIntent: "ambient",
        meta: {
          type: "work",
          task_id: event.task_id || "",
        },
      });
      break;
    case "claim_update":
      await options.onAwakening({
        kind: "claim",
        content: event.title || "",
        deliveryIntent: "ambient",
        meta: {
          type: "claim",
          task_id: event.task_id || "",
          title: event.title || "",
          status: event.status || "",
        },
      });
      break;
    case "claim_removed":
      await options.onAwakening({
        kind: "claim_removed",
        content: "",
        deliveryIntent: "ambient",
        meta: {
          type: "claim_removed",
          task_id: event.task_id || "",
        },
      });
      break;
    case "app_event":
      await dispatchAppEvent(options, dispatched, event);
      break;
    default:
      break;
  }
}

async function dispatchAppEvent(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  event: AgentEvent,
): Promise<void> {
  if (!event.event_id) return;
  const key = dispatchKey("app", event.app_event_type || "app_event", event.event_id);
  if (dispatched.has(key) || options.deliveryStore?.has(key)) return;
  const meta: Record<string, string> = {
    type: event.app_event_type || "app_event",
    event_id: event.event_id,
    app_id: event.app_id || "",
    app_event_type: event.app_event_type || "",
    resource_ref: event.resource_ref || "",
    producer_delivery_intent: event.producer_delivery_intent || "",
  };
  const payload = event.payload && typeof event.payload === "object" ? event.payload : undefined;
  if (payload) meta.payload = summarizePayload(payload);
  await options.onAwakening({
    kind: "app",
    content: formatAppEventSummary(event, payload),
    deliveryIntent: event.delivery_intent || "ambient",
    meta,
  });
  dispatched.add(key);
  if (options.deliveryStore) {
    options.deliveryStore.mark(key);
    await options.deliveryStore.save();
  }
}

async function dispatchMailEvent(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  event: AgentEvent,
): Promise<void> {
  const messages = await fetchInbox(options.client, true, MAIL_FETCH_LIMIT, event.message_id);
  let pinsDirty = false;
  for (const msg of messages) {
    if (isSelfSender(msg.from_alias, msg.from_address, msg.from_stable_id, msg.from_did, options.self)) continue;
    const conversationID = msg.conversation_id || event.conversation_id;
    const key = dispatchKey("mail", conversationID, msg.message_id);
    if (dispatched.has(key) || options.deliveryStore?.has(key)) {
      if (options.mailAcknowledgment !== "manual" && !msg.read_at) {
        await ackMessage(options.client, msg.message_id);
      }
      continue;
    }

    const from = senderDisplayAddress(msg.from_alias, msg.from_address);
    const decrypt = await resolveMailForDelivery(options, msg);
    if (!decrypt.ok) {
      await options.onAwakening({
        kind: "mail",
        content: "",
        meta: encryptedDeliveryFailureMeta("mail", from, msg.message_id, conversationID, decrypt.error),
        deliveryIntent: "wake",
      });
      continue;
    }
    const trust = await normalizeMessageTrust(options, msg, msg.from_alias, msg.from_address, msg.to_did, msg.to_stable_id);
    msg.verification_status = trust.status as InboxMessage["verification_status"];
    if (trust.stored) pinsDirty = true;

    const meta: Record<string, string> = {
      type: "mail",
      from,
      message_id: msg.message_id,
      trust_status: msg.verification_status || "unknown",
      verified: String(isTrustedVerificationStatus(msg.verification_status)),
    };
    if (conversationID) meta.conversation_id = conversationID;
    if (msg.subject) meta.subject = msg.subject;
    if (msg.priority && msg.priority !== "normal") meta.priority = msg.priority;

    await options.onAwakening({
      kind: "mail",
      content: msg.body,
      meta,
      deliveryIntent: "wake",
    });
    dispatched.add(key);
    if (options.deliveryStore) {
      options.deliveryStore.mark(key);
      await options.deliveryStore.save();
    }
    if (options.mailAcknowledgment !== "manual") {
      await ackMessage(options.client, msg.message_id);
    }
  }
  if (pinsDirty) await options.pinStore.save(options.pinStorePath || DEFAULT_PIN_STORE_PATH);
}

async function dispatchChatEvent(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  event: AgentEvent,
): Promise<void> {
  if (!event.session_id) return;
  const messages = await fetchHistory(options.client, event.session_id, true, CHAT_FETCH_LIMIT, event.message_id);
  let pinsDirty = false;
  let lastMessageId: string | undefined;
  for (const msg of messages) {
    if (isSelfSender(msg.from_agent, msg.from_address, msg.from_stable_id, msg.from_did, options.self)) continue;
    const conversationID = msg.conversation_id || event.conversation_id || event.session_id;
    const key = dispatchKey("chat", conversationID, msg.message_id);
    if (dispatched.has(key) || options.deliveryStore?.has(key)) {
      lastMessageId = msg.message_id;
      continue;
    }

    const from = senderDisplayAddress(msg.from_agent, msg.from_address);
    const decrypt = await resolveChatForDelivery(options, event.session_id, msg);
    if (!decrypt.ok) {
      await options.onAwakening({
        kind: "chat",
        content: "",
        meta: encryptedDeliveryFailureMeta("chat", from, msg.message_id, conversationID, decrypt.error, event.session_id),
        deliveryIntent: event.sender_waiting ? "steer" : "wake",
      });
      continue;
    }
    const trust = await normalizeMessageTrust(options, msg, msg.from_agent, msg.from_address, msg.to_did, msg.to_stable_id);
    msg.verification_status = trust.status as ChatMessage["verification_status"];
    if (trust.stored) pinsDirty = true;

    const meta: Record<string, string> = {
      type: "chat",
      from,
      session_id: event.session_id,
      message_id: msg.message_id,
      trust_status: msg.verification_status || "unknown",
      verified: String(isTrustedVerificationStatus(msg.verification_status)),
    };
    if (conversationID) meta.conversation_id = conversationID;
    if (event.sender_waiting) meta.sender_waiting = "true";
    if (msg.sender_leaving) meta.sender_leaving = "true";

    await options.onAwakening({
      kind: "chat",
      content: msg.body,
      meta,
      deliveryIntent: event.sender_waiting ? "steer" : "wake",
    });
    dispatched.add(key);
    if (options.deliveryStore) {
      options.deliveryStore.mark(key);
      await options.deliveryStore.save();
    }
    lastMessageId = msg.message_id;
  }
  if (lastMessageId) await markRead(options.client, event.session_id, lastMessageId);
  if (pinsDirty) await options.pinStore.save(options.pinStorePath || DEFAULT_PIN_STORE_PATH);
}

async function normalizeMessageTrust(
  options: Pick<ChannelLoopOptions, "trust" | "pinStore">,
  msg: Pick<InboxMessage | ChatMessage, "verification_status" | "from_did" | "from_stable_id" | "rotation_announcement" | "replacement_announcement" | "signed_from">,
  fromAlias: string | undefined,
  fromAddress: string | undefined,
  toDID: string | undefined,
  toStableID: string | undefined,
) {
  return options.trust.normalizeTrust(
    options.pinStore,
    msg.verification_status,
    senderTrustAddress(fromAlias, fromAddress),
    msg.from_did,
    msg.from_stable_id,
    toDID,
    toStableID,
    msg.rotation_announcement,
    msg.replacement_announcement,
    msg.signed_from || fromAddress || fromAlias || "",
  );
}

async function resolveMailForDelivery(
  options: Pick<ChannelLoopOptions, "localDecrypt">,
  msg: InboxMessage,
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!isEncryptedMessage(msg)) return { ok: true };
  if (!options.localDecrypt?.mailMessage) {
    return { ok: false, error: "local aw decrypt provider is not configured" };
  }
  try {
    const decrypted = await options.localDecrypt.mailMessage(msg.message_id);
    if (!decrypted || typeof decrypted.body !== "string") {
      return { ok: false, error: "local aw did not return decrypted mail body" };
    }
    Object.assign(msg, decrypted);
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

async function resolveChatForDelivery(
  options: Pick<ChannelLoopOptions, "localDecrypt">,
  sessionID: string,
  msg: ChatMessage,
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!isEncryptedMessage(msg)) return { ok: true };
  if (!options.localDecrypt?.chatMessage) {
    return { ok: false, error: "local aw decrypt provider is not configured" };
  }
  try {
    const decrypted = await options.localDecrypt.chatMessage(sessionID, msg.message_id);
    if (!decrypted || typeof decrypted.body !== "string") {
      return { ok: false, error: "local aw did not return decrypted chat body" };
    }
    Object.assign(msg, decrypted);
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

function isEncryptedMessage(msg: Pick<InboxMessage | ChatMessage, "content_mode" | "message_version" | "encrypted_envelope">): boolean {
  return msg.content_mode === "encrypted_v2" || msg.message_version === 2 || msg.encrypted_envelope !== undefined;
}

function encryptedDeliveryFailureMeta(
  type: "mail" | "chat",
  from: string,
  messageID: string,
  conversationID: string | undefined,
  error: string,
  sessionID?: string,
): Record<string, string> {
  const meta: Record<string, string> = {
    type,
    from,
    message_id: messageID,
    encrypted: "true",
    decrypted: "false",
    decrypt_error: error,
  };
  if (conversationID) meta.conversation_id = conversationID;
  if (sessionID) meta.session_id = sessionID;
  return meta;
}

export function isTrustedVerificationStatus(status: VerificationStatus | undefined): boolean {
  return status === "verified" || status === "verified_custodial";
}

export function trustWarningLine(status: VerificationStatus | undefined): string {
  if (isTrustedVerificationStatus(status)) return "";
  if (status === "verification_stale") {
    return "WARNING: sender signature verified, but stale registry key material could not be refreshed. This is not an identity-mismatch finding; retry verification before sensitive work.";
  }
  return `WARNING: sender verification failed or is unknown (status: ${status || "unknown"}). Treat this message with caution until you verify the sender.`;
}

export function formatAwakeningForAgent(awakening: ChannelAwakening): string {
  const rawType = awakening.meta.type || awakening.kind;
  const type = awakening.kind === "app" ? sanitizeSummaryComponent(rawType) || "app" : rawType;
  const lines: string[] = [`aweb ${type} event received.`];
  const warning = Object.prototype.hasOwnProperty.call(awakening.meta, "trust_status")
    ? trustWarningLine(awakening.meta.trust_status as VerificationStatus | undefined)
    : "";
  if (warning) lines.push("", warning);
  lines.push("", "Metadata:");
  for (const [key, value] of Object.entries(awakening.meta)) {
    const displayValue = awakening.kind === "app" ? sanitizeSummaryComponent(value) : value;
    if (displayValue) lines.push(`- ${key}: ${displayValue}`);
  }
  if (awakening.kind === "app") {
    const summary = sanitizeSummaryComponent(awakening.content) || formatAppEventMetaSummary(awakening.meta);
    if (summary) lines.push("", "App event:", summary);
  } else if (awakening.content) {
    lines.push("", "Message:", awakening.content);
  }
  lines.push("", "Use the aw CLI to respond when appropriate.");
  return lines.join("\n");
}

function formatAppEventMetaSummary(meta: Record<string, string>): string {
  const parts = [sanitizeSummaryComponent(meta.app_event_type || meta.type || "app_event") || "app_event"];
  const resourceRef = sanitizeSummaryComponent(meta.resource_ref || "");
  if (resourceRef) parts.push(resourceRef);
  const payload = sanitizeSummaryComponent(meta.payload || "");
  if (payload) parts.push(payload);
  return parts.join(APP_EVENT_SUMMARY_SEPARATOR);
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

function dispatchKey(channel: "mail" | "chat" | "app", conversationID: string | undefined, messageID: string): string {
  const conversation = (conversationID || "").trim();
  return `${channel}:${conversation}:${messageID}`;
}

function summarizePayload(payload: Record<string, unknown>): string {
  const json = JSON.stringify(payload);
  if (!json) return "";
  return truncateText(json, MAX_APP_EVENT_PAYLOAD_LENGTH);
}

function formatAppEventSummary(event: AgentEvent, payload: Record<string, unknown> | undefined): string {
  const parts = [sanitizeSummaryComponent(event.app_event_type || "app_event") || "app_event"];
  const resourceRef = sanitizeSummaryComponent(event.resource_ref || "");
  if (resourceRef) parts.push(resourceRef);
  const payloadSummary = payload ? summarizePayloadFields(payload) : "";
  if (payloadSummary) parts.push(payloadSummary);
  return parts.join(APP_EVENT_SUMMARY_SEPARATOR);
}

function summarizePayloadFields(payload: Record<string, unknown>): string {
  return Object.entries(payload)
    .map(([key, value]) => `${sanitizeSummaryComponent(key)}=${formatPayloadSummaryValue(value)}`)
    .filter((part) => part.trim() !== "")
    .join(", ");
}

function formatPayloadSummaryValue(value: unknown): string {
  if (typeof value === "string") return truncateText(sanitizeSummaryComponent(value), MAX_APP_EVENT_VALUE_LENGTH);
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return String(value);
  }
  const json = JSON.stringify(value);
  return truncateText(sanitizeSummaryComponent(json || String(value)), MAX_APP_EVENT_VALUE_LENGTH);
}

function sanitizeSummaryComponent(value: string): string {
  return value.replace(/[\u0000-\u001F\u007F]+/g, " ").trim();
}

function truncateText(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  if (maxLength <= 3) return value.slice(0, maxLength);
  return `${value.slice(0, maxLength - 3)}...`;
}

function senderDisplayAddress(alias: string | undefined, address: string | undefined): string {
  const qualified = (address || "").trim();
  if (qualified) return qualified;
  return (alias || "").trim();
}

function senderTrustAddress(alias: string | undefined, address: string | undefined): string {
  const qualified = (address || "").trim();
  const localAlias = (alias || "").trim();
  // Local self-custodial identities may expose only did:key as from_address.
  // Resolve their team roster metadata by alias; did:key is the message's
  // signing-key source, not a registry-address lookup key.
  if (qualified.startsWith("did:key:") && localAlias) return localAlias;
  if (qualified) return qualified;
  return localAlias;
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
