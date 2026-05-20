import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { mkdir, readFile, writeFile } from "node:fs/promises";

import { APIClient } from "./api/client.js";
import { streamAgentEvents, type AgentEvent } from "./api/events.js";
import { ackMessage, fetchInbox, type InboxMessage } from "./api/mail.js";
import { fetchHistory, markRead, type ChatMessage } from "./api/chat.js";
import { PinStore } from "./identity/pinstore.js";
import { RegistryResolver } from "./identity/registry.js";
import { SenderTrustManager } from "./identity/trust.js";
import type { VerificationStatus } from "./identity/signing.js";

export const DEFAULT_PIN_STORE_PATH = join(homedir(), ".config", "aw", "known_agents.yaml");
export const DEFAULT_DELIVERY_STORE_PATH = join(homedir(), ".config", "aw", "channel-delivered-ids.json");
const MAX_DISPATCHED_IDS = 2000;
const MAX_DELIVERED_IDS = 5000;
const DELIVERED_IDS_TTL_MS = 24 * 60 * 60 * 1000;
const MAIL_FETCH_LIMIT = 200;
const CHAT_FETCH_LIMIT = 2000;

export interface SelfIdentity {
  alias: string;
  address: string;
  did: string;
  stableID: string;
}

export type ChannelAwakeningKind = "mail" | "chat" | "control" | "work" | "claim" | "claim_removed";
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
  deliveryStore?: DeliveryStore;
  log?: (message: string) => void;
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
  const log = options.log || (() => {});

  for await (const event of streamAgentEvents(options.client, options.signal)) {
    try {
      await dispatchAgentEvent({ ...options, deliveryStore }, dispatched, event);
      pruneDispatched(dispatched);
    } catch (err) {
      log(`[aw-channel] dispatch error: ${err}`);
    }
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
    default:
      break;
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
      if (!msg.read_at) await ackMessage(options.client, msg.message_id);
      continue;
    }

    const from = senderDisplayAddress(msg.from_alias, msg.from_address);
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
    await ackMessage(options.client, msg.message_id);
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

export function isTrustedVerificationStatus(status: VerificationStatus | undefined): boolean {
  return status === "verified" || status === "verified_custodial";
}

export function trustWarningLine(status: VerificationStatus | undefined): string {
  if (isTrustedVerificationStatus(status)) return "";
  return `WARNING: sender verification failed or is unknown (status: ${status || "unknown"}). Treat this message with caution until you verify the sender.`;
}

export function formatAwakeningForAgent(awakening: ChannelAwakening): string {
  const type = awakening.meta.type || awakening.kind;
  const lines: string[] = [`aweb ${type} event received.`];
  const warning = Object.prototype.hasOwnProperty.call(awakening.meta, "trust_status")
    ? trustWarningLine(awakening.meta.trust_status as VerificationStatus | undefined)
    : "";
  if (warning) lines.push("", warning);
  lines.push("", "Metadata:");
  for (const [key, value] of Object.entries(awakening.meta)) {
    if (value) lines.push(`- ${key}: ${value}`);
  }
  if (awakening.content) {
    lines.push("", "Message:", awakening.content);
  }
  lines.push("", "Use the aw CLI to respond when appropriate.");
  return lines.join("\n");
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

function dispatchKey(channel: "mail" | "chat", conversationID: string | undefined, messageID: string): string {
  const conversation = (conversationID || "").trim();
  return `${channel}:${conversation}:${messageID}`;
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
