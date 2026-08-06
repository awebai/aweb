import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { appendFile, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { lock } from "proper-lockfile";

import { APIClient } from "./api/client.js";
import { streamAgentEvents, type AgentEvent, type EventStreamState } from "./api/events.js";
import { ackMessage, fetchInbox, type InboxMessage } from "./api/mail.js";
import { fetchHistory, markRead, type ChatMessage } from "./api/chat.js";
import { PinStore, type PinStoreWriter } from "./identity/pinstore.js";
import { RegistryResolver } from "./identity/registry.js";
import { SenderTrustManager } from "./identity/trust.js";
import type { VerificationStatus } from "./identity/signing.js";
import {
  createLocalAWDecryptProvider,
  createLocalAWPinStoreWriter,
  PinStoreCASConflictError,
  type LocalDecryptProvider,
} from "./local_aw.js";

export const DEFAULT_PIN_STORE_PATH = join(homedir(), ".config", "aw", "known_agents.yaml");
export const DEFAULT_DELIVERY_STORE_PATH = join(homedir(), ".config", "aw", "channel-delivered-ids.json");
export const DEFAULT_UNDELIVERED_LOG_PATH = join(homedir(), ".config", "aw", "channel-undelivered.jsonl");
const MAX_DISPATCHED_IDS = 2000;
const MAX_DELIVERED_IDS = 5000;
const PROMOTED_DELIVERY_KEY_PREFIX = "__aweb_promoted__:";
const DELIVERED_IDS_TTL_MS = 24 * 60 * 60 * 1000;
const MAIL_FETCH_LIMIT = 200;
const MAIL_STARTUP_CATCH_UP_LIMIT = 20;
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

interface PendingMailDelivery {
  key: string;
  messageID: string;
}

const pendingMailDeliveries = new WeakMap<Set<string>, Map<string, PendingMailDelivery>>();

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
  deliveryStorePath?: string;
  undeliveredLog?: UndeliveredLog;
  undeliveredLogPath?: string;
  localDecrypt?: LocalDecryptProvider;
  teamID?: string;
  workdir?: string;
  awCommand?: string;
  pinStoreWriter?: PinStoreWriter;
  log?: (message: string) => void;
  onStreamState?: (state: EventStreamState) => void;
}

export async function loadPinStore(path: string = DEFAULT_PIN_STORE_PATH): Promise<PinStore> {
  let content: string;
  try {
    content = await readFile(path, "utf-8");
  } catch (error) {
    // Only a genuinely absent file is a fresh first-run empty store. Any other
    // read failure (permissions, I/O) must fail closed so corruption is never
    // silently converted into unannounced first contact.
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") {
      return new PinStore();
    }
    throw new Error(
      `cannot read trust pin store at ${path} (${(error as NodeJS.ErrnoException)?.code ?? "read error"}); refusing to start without the trust database`,
    );
  }
  try {
    return PinStore.fromYAML(content);
  } catch (error) {
    throw new Error(
      `trust pin store at ${path} is corrupt: ${(error as Error).message}; refusing to start (the existing file is left unchanged — repair or remove it)`,
    );
  }
}

/**
 * Load the pin store for an adapter session. On any load failure it reports the
 * error and returns undefined — never a fresh empty store — so an adapter fails
 * closed instead of silently starting with a discarded trust database. Adapters
 * MUST treat undefined as "do not start the channel".
 */
export async function loadSessionPinStore(
  onError: (message: string) => void,
  load: () => Promise<PinStore> = loadPinStore,
): Promise<PinStore | undefined> {
  try {
    return await load();
  } catch (error) {
    onError(error instanceof Error ? error.message : String(error));
    return undefined;
  }
}

interface DeliveryStoreEntry {
  timestamp: number;
  promoted: boolean;
}

export class DeliveryStore {
  private constructor(
    private readonly path: string,
    private entries: Map<string, DeliveryStoreEntry>,
  ) {}

  static async load(path: string = DEFAULT_DELIVERY_STORE_PATH): Promise<DeliveryStore> {
    return new DeliveryStore(path, await DeliveryStore.readEntries(path));
  }

  // Read the on-disk marks, dropping expired ones. Only an absent file is a
  // fresh empty store; unreadable or malformed state must remain visible so a
  // later save cannot silently overwrite every durable delivery mark.
  private static async readEntries(path: string): Promise<Map<string, DeliveryStoreEntry>> {
    let content: string;
    try {
      content = await readFile(path, "utf-8");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return new Map();
      return DeliveryStore.quarantine(path, `cannot read it (${code ?? "read error"})`, error);
    }

    let raw: unknown;
    try {
      raw = JSON.parse(content);
    } catch (error) {
      return DeliveryStore.quarantine(path, `its JSON is malformed: ${(error as Error).message}`, error);
    }
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      return DeliveryStore.quarantine(path, "it does not contain a JSON object");
    }

    const entries = new Map<string, DeliveryStoreEntry>();
    const promoted = new Map<string, number>();
    const now = Date.now();
    for (const [storedKey, value] of Object.entries(raw)) {
      let timestamp: number;
      if (typeof value === "number") timestamp = value;
      else if (typeof value === "string") timestamp = Date.parse(value);
      else timestamp = Number.NaN;
      if (!Number.isFinite(timestamp)) {
        return DeliveryStore.quarantine(path, `mark ${JSON.stringify(storedKey)} has an invalid timestamp`);
      }
      if (now - timestamp > DELIVERED_IDS_TTL_MS) continue;
      if (storedKey.startsWith(PROMOTED_DELIVERY_KEY_PREFIX)) {
        promoted.set(storedKey.slice(PROMOTED_DELIVERY_KEY_PREFIX.length), timestamp);
      } else {
        entries.set(storedKey, { timestamp, promoted: false });
      }
    }
    for (const [key, promotedAt] of promoted) {
      const entry = entries.get(key);
      if (entry) {
        entry.timestamp = Math.max(entry.timestamp, promotedAt);
        entry.promoted = true;
      }
    }
    return entries;
  }

  private static async quarantine(path: string, reason: string, cause?: unknown): Promise<never> {
    const quarantinePath = `${path}.corrupt-${Date.now()}-${process.pid}-${DeliveryStore.quarantineCounter += 1}`;
    try {
      await rename(path, quarantinePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error(
          `delivery store at ${path} was quarantined concurrently after detection (${reason}); retry the operation`,
          { cause: cause ?? error },
        );
      }
      throw new Error(
        `delivery store at ${path} is corrupt (${reason}) and could not be quarantined (${(error as NodeJS.ErrnoException).code ?? "rename error"}); refusing to overwrite it`,
        { cause: cause ?? error },
      );
    }
    throw new Error(
      `delivery store at ${path} was quarantined at ${quarantinePath} because ${reason}; retry the operation to start a fresh store`,
      { cause },
    );
  }

  has(key: string): boolean {
    this.prune();
    return this.entries.has(key);
  }

  isLegacy(key: string): boolean {
    this.prune();
    return this.entries.get(key)?.promoted === false;
  }

  hasLegacyEntries(): boolean {
    this.prune();
    return [...this.entries.values()].some((entry) => !entry.promoted);
  }

  mark(key: string): void {
    this.entries.set(key, { timestamp: Date.now(), promoted: true });
    this.prune();
  }

  unmark(key: string): void {
    this.entries.delete(key);
  }

  // Persist marks with an atomic, merge-on-save read-modify-write. A plain
  // overwrite would clobber marks another writer added since we loaded — making
  // delivered messages look undelivered and replay on reconnect (default-aajy).
  // The complete transaction must be cross-process exclusive: readback retries
  // can each observe success before a later rename silently replaces it.
  async save(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const own = new Map(this.entries);
    // Node has no portable flock, so use a maintained atomic-directory lock
    // rather than a bespoke stale-lock protocol. A healthy owner heartbeats at
    // 10s and remains live beyond the 30s stale threshold. Each competing save,
    // including immediately after SIGKILL, gives up with ELOCKED after about 5s;
    // only a later call made after the lock age exceeds 30s can reclaim it. A
    // false reclaim can cause redelivery but cannot cross a trust boundary.
    let compromised: Error | undefined;
    const release = await lock(this.path, {
      realpath: false,
      stale: 30_000,
      update: 10_000,
      retries: {
        retries: 200,
        factor: 1,
        minTimeout: 25,
        maxTimeout: 25,
        randomize: true,
      },
      onCompromised: (error) => { compromised = error; },
    });
    try {
      const merged = await DeliveryStore.readEntries(this.path);
      for (const [key, value] of own) {
        const existing = merged.get(key);
        if (existing === undefined) {
          merged.set(key, value);
        } else {
          merged.set(key, {
            timestamp: Math.max(existing.timestamp, value.timestamp),
            promoted: existing.promoted || value.promoted,
          });
        }
      }
      this.entries = merged;
      this.prune();
      await this.writeAtomic();
      if (compromised) throw compromised;
    } finally {
      if (!compromised) await release();
    }
  }

  private async writeAtomic(): Promise<void> {
    // Keep every value in the historical timestamp-string shape so an older
    // channel process sharing this store can still load and deduplicate it. A
    // reserved companion key carries the new promoted state; old readers simply
    // retain that harmless extra mark instead of quarantining the whole store.
    const payload: Record<string, string> = {};
    for (const [key, value] of this.entries) {
      const timestamp = new Date(value.timestamp).toISOString();
      payload[key] = timestamp;
      if (value.promoted) payload[`${PROMOTED_DELIVERY_KEY_PREFIX}${key}`] = timestamp;
    }
    const data = `${JSON.stringify(payload, null, 2)}\n`;
    // O_EXCL temp + atomic rename, symlink-safe, mode 0600 — matching the pin
    // store (aajc.2), so a crash mid-write cannot corrupt the store.
    const tmp = `${this.path}.tmp-${process.pid}-${Date.now()}-${DeliveryStore.tmpCounter += 1}`;
    const file = await open(tmp, "wx", 0o600);
    try {
      await file.writeFile(data, "utf-8");
      await file.sync();
    } catch (error) {
      await file.close().catch(() => {});
      await rm(tmp, { force: true }).catch(() => {});
      throw error;
    }
    await file.close();
    await rename(tmp, this.path);
  }

  private static tmpCounter = 0;
  private static quarantineCounter = 0;

  private prune(): void {
    const now = Date.now();
    for (const [key, value] of this.entries) {
      if (now - value.timestamp > DELIVERED_IDS_TTL_MS) this.entries.delete(key);
    }
    if (this.entries.size <= MAX_DELIVERED_IDS) return;
    const sorted = [...this.entries.entries()].sort((a, b) => a[1].timestamp - b[1].timestamp);
    for (const [key] of sorted.slice(0, this.entries.size - MAX_DELIVERED_IDS)) {
      this.entries.delete(key);
    }
  }
}

/**
 * Append-only record of the messages the channel declined to present.
 *
 * A message that is never presented otherwise leaves no trace at all: the skip
 * happens before the delivery mark and before the trust record, the server holds
 * only read_at — which cannot distinguish a dropped message from a read one —
 * and the channel's own log goes to stderr. So a delivery failure can only be
 * reconstructed from message metadata, if at all (aweb-aawv).
 *
 * Deliberately not a DeliveryStore. These entries carry no TTL and are never
 * rewritten: expiring or overwriting the evidence would recreate the gap this
 * record exists to close.
 */
export class UndeliveredLog {
  constructor(private readonly path: string) {}

  async record(entry: { messageID: string; from: string; reason: string }): Promise<void> {
    const line = JSON.stringify({
      message_id: entry.messageID,
      from: entry.from,
      reason: entry.reason,
      at: new Date().toISOString(),
    });
    await mkdir(dirname(this.path), { recursive: true });
    await appendFile(this.path, `${line}\n`, { encoding: "utf-8", mode: 0o600 });
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
  const client = new APIClient(config.baseURL, {
    did: config.did,
    stableID: config.stableID,
    signingKey: config.signingKey,
    teamID: config.teamID,
    teamCertificateHeader: config.teamCertificateHeader,
  });
  if (!client.hasTeamCertificateAuth(config.teamID)) {
    throw new Error(`selected active team ${config.teamID} is missing certificate signing authentication`);
  }
  return client;
}

export async function startChannelLoop(options: ChannelLoopOptions & { teamID: string }): Promise<void> {
  const dispatched = new Set<string>();
  // Per-agent delivery store: one global file shared by every agent on the host
  // let ~95 concurrent agents clobber each other's marks (default-aajy). Scope
  // it to this agent's workspace (.aw) so each writes its own file.
  const deliveryStorePath = options.deliveryStorePath
    || (options.workdir ? join(options.workdir, ".aw", "channel-delivered-ids.json") : DEFAULT_DELIVERY_STORE_PATH);
  const deliveryStore = options.deliveryStore || await DeliveryStore.load(deliveryStorePath);
  const undeliveredLogPath = options.undeliveredLogPath
    || (options.workdir ? join(options.workdir, ".aw", "channel-undelivered.jsonl") : DEFAULT_UNDELIVERED_LOG_PATH);
  const undeliveredLog = options.undeliveredLog || new UndeliveredLog(undeliveredLogPath);
  const localDecrypt = options.localDecrypt || (
    options.workdir ? createLocalAWDecryptProvider({
      workdir: options.workdir,
      awCommand: options.awCommand,
      teamID: options.teamID,
    }) : undefined
  );
  const wiredOptions = { ...options, deliveryStore, undeliveredLog, localDecrypt };
  const log = options.log || (() => {});
  await catchUpLegacyMail(wiredOptions, dispatched, log);
  await consumeAgentEvents(
    // UNGUARDED: no test covers this function, so removing any dependency from
    // this spread silently disables it rather than failing. Deleting
    // undeliveredLog here leaves all 281 tests passing while the channel stops
    // recording dropped messages entirely. See aweb-aayl.
    wiredOptions,
    dispatched,
    streamAgentEvents(options.client, options.signal, options.onStreamState),
    log,
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
        await dispatchAgentEvent(options, dispatched, event, log);
        pruneDispatched(dispatched);
      })
      .catch((error) => {
        const detail = error instanceof Error ? error.message : String(error);
        log(`aweb: could not process an incoming event: ${detail}; it remains pending`);
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
  log: (message: string) => void = (message) => console.error(message),
): Promise<void> {
  const promotable = [...(pendingMailDeliveries.get(dispatched)?.values() || [])];
  switch (event.type) {
    case "mail_message":
      await dispatchMailEvent(options, dispatched, event, log);
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
  await promotePendingMail(options, dispatched, promotable);
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
  await persistDeliveryMark(options.deliveryStore, dispatched, key);
}

async function catchUpLegacyMail(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  log: (message: string) => void,
): Promise<void> {
  if (!options.deliveryStore?.hasLegacyEntries()) return;
  const messages = await fetchInbox(
    options.client,
    false,
    MAIL_STARTUP_CATCH_UP_LIMIT,
    undefined,
    log,
  );
  await dispatchMailMessages(
    options,
    dispatched,
    {},
    messages.slice(0, MAIL_STARTUP_CATCH_UP_LIMIT),
    log,
    true,
  );
}

async function dispatchMailEvent(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  event: AgentEvent,
  log: (message: string) => void,
): Promise<void> {
  const messages = await fetchInbox(options.client, true, MAIL_FETCH_LIMIT, event.message_id, log);
  await dispatchMailMessages(options, dispatched, event, messages, log, false);
}

async function dispatchMailMessages(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  event: Pick<AgentEvent, "conversation_id">,
  messages: InboxMessage[],
  log: (message: string) => void,
  legacyOnly: boolean,
): Promise<void> {
  for (const msg of messages) {
    if (msg.verification_error) {
      // An audit write must never fail the delivery it observes. This message is
      // deliberately left unread and unacked, so it returns in every unread-only
      // fetch; letting a write failure escape would abort the rest of the batch
      // and do so again on each fetch, stopping delivery behind a message that
      // can never be cleared. Contrast persistDeliveryMark below, which rethrows
      // on purpose: a failed delivery mark must not become an acknowledgment.
      // This record carries no such contract, so it fails soft and reports.
      try {
        await options.undeliveredLog?.record({
          messageID: msg.message_id,
          from: senderDisplayAddress(msg.from_alias, msg.from_address),
          reason: "verification_error",
        });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        log(`aweb: could not record undelivered message ${JSON.stringify(msg.message_id)}: ${detail}`);
      }
      continue;
    }
    if (isSelfSender(msg.from_alias, msg.from_address, msg.from_stable_id, msg.from_did, options.self)) continue;
    const conversationID = msg.conversation_id || event.conversation_id;
    const key = dispatchKey("mail", conversationID, msg.message_id);
    const legacy = options.deliveryStore?.isLegacy(key) === true;
    if (legacyOnly && !legacy) continue;
    if (dispatched.has(key)) continue;
    if (options.deliveryStore?.has(key) && !legacy) {
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
    const trust = await normalizeAndPersistMessageTrust(
      options,
      msg,
      msg.from_alias,
      msg.from_address,
      msg.to_did,
      msg.to_stable_id,
    );
    msg.verification_status = trust.status as InboxMessage["verification_status"];

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
    stagePendingMail(dispatched, key, msg.message_id);
  }
}

async function dispatchChatEvent(
  options: Omit<ChannelLoopOptions, "signal" | "log">,
  dispatched: Set<string>,
  event: AgentEvent,
): Promise<void> {
  if (!event.session_id) return;
  const messages = await fetchHistory(options.client, event.session_id, true, CHAT_FETCH_LIMIT, event.message_id);
  const presentedMessageIds: string[] = [];
  for (const msg of messages) {
    if (isSelfSender(msg.from_agent, msg.from_address, msg.from_stable_id, msg.from_did, options.self)) continue;
    const conversationID = msg.conversation_id || event.conversation_id || event.session_id;
    const key = dispatchKey("chat", conversationID, msg.message_id);
    if (dispatched.has(key) || options.deliveryStore?.has(key)) {
      presentedMessageIds.push(msg.message_id);
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
    const trust = await normalizeAndPersistMessageTrust(
      options,
      msg,
      msg.from_agent,
      msg.from_address,
      msg.to_did,
      msg.to_stable_id,
    );
    msg.verification_status = trust.status as ChatMessage["verification_status"];

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
    await persistDeliveryMark(options.deliveryStore, dispatched, key);
    presentedMessageIds.push(msg.message_id);
  }
  if (presentedMessageIds.length > 0) {
    await markRead(options.client, event.session_id, presentedMessageIds);
  }
}

async function commitPinStore(
  options: Pick<ChannelLoopOptions, "pinStore" | "pinStorePath" | "pinStoreWriter" | "workdir" | "awCommand">,
): Promise<void> {
  const writer = options.pinStoreWriter || createLocalAWPinStoreWriter({
    workdir: options.workdir,
    awCommand: options.awCommand,
  });
  const path = options.pinStorePath || DEFAULT_PIN_STORE_PATH;
  try {
    await options.pinStore.commit(writer, path);
  } catch (error) {
    if (error instanceof PinStoreCASConflictError) {
      options.pinStore.replaceWithDurableState(await loadPinStore(path));
    }
    throw error;
  }
}

async function normalizeAndPersistMessageTrust(
  options: Pick<ChannelLoopOptions, "trust" | "pinStore" | "pinStorePath" | "pinStoreWriter" | "workdir" | "awCommand">,
  msg: Pick<InboxMessage | ChatMessage, "verification_status" | "from_did" | "from_stable_id" | "rotation_announcement" | "replacement_announcement" | "signed_from">,
  fromAlias: string | undefined,
  fromAddress: string | undefined,
  toDID: string | undefined,
  toStableID: string | undefined,
) {
  return options.pinStore.runExclusive(async () => {
    const trust = await normalizeMessageTrust(
      options,
      msg,
      fromAlias,
      fromAddress,
      toDID,
      toStableID,
    );
    if (trust.stored || options.pinStore.hasUndurableChanges()) {
      await commitPinStore(options);
    }
    return trust;
  });
}

function stagePendingMail(
  dispatched: Set<string>,
  key: string,
  messageID: string,
): void {
  let pending = pendingMailDeliveries.get(dispatched);
  if (!pending) {
    pending = new Map();
    pendingMailDeliveries.set(dispatched, pending);
  }
  pending.set(key, { key, messageID });
  dispatched.add(key);
}

async function promotePendingMail(
  options: Pick<ChannelLoopOptions, "client" | "deliveryStore" | "mailAcknowledgment">,
  dispatched: Set<string>,
  promotable: PendingMailDelivery[],
): Promise<void> {
  const pending = pendingMailDeliveries.get(dispatched);
  for (const delivery of promotable) {
    if (pending?.get(delivery.key) !== delivery) continue;
    await persistDeliveryMark(options.deliveryStore, dispatched, delivery.key);
    if (options.mailAcknowledgment !== "manual") {
      await ackMessage(options.client, delivery.messageID);
    }
    pending.delete(delivery.key);
  }
  if (pending?.size === 0) pendingMailDeliveries.delete(dispatched);
}

async function persistDeliveryMark(
  deliveryStore: DeliveryStore | undefined,
  dispatched: Set<string>,
  key: string,
): Promise<void> {
  if (deliveryStore) {
    deliveryStore.mark(key);
    try {
      await deliveryStore.save();
    } catch (error) {
      // A transient in-memory mark must not turn a failed durable save into an
      // acknowledgment on the next event. Leave the message pending instead.
      deliveryStore.unmark(key);
      throw error;
    }
  }
  dispatched.add(key);
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
    msg.subject = decrypted.subject;
    msg.body = decrypted.body;
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
    msg.body = decrypted.body;
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

function isEncryptedMessage(msg: Pick<InboxMessage | ChatMessage, "content_mode" | "message_version" | "encrypted_envelope">): boolean {
  return msg.content_mode === "encrypted_v2" || msg.message_version === 2 || msg.encrypted_envelope != null;
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
  if (status === "pin_conflict") {
    return "WARNING: two pin records conflict for this sender. Stable-identity migration was refused to avoid discarding trust state; inspect and repair the pin store before trusting the sender.";
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
