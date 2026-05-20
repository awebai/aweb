import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { APIClient } from "./api/client.js";
import { streamAgentEvents } from "./api/events.js";
import { ackMessage, fetchInbox } from "./api/mail.js";
import { fetchHistory, markRead } from "./api/chat.js";
import { PinStore } from "./identity/pinstore.js";
import { RegistryResolver } from "./identity/registry.js";
export const DEFAULT_PIN_STORE_PATH = join(homedir(), ".config", "aw", "known_agents.yaml");
export const DEFAULT_DELIVERY_STORE_PATH = join(homedir(), ".config", "aw", "channel-delivered-ids.json");
const MAX_DISPATCHED_IDS = 2000;
const MAX_DELIVERED_IDS = 5000;
const DELIVERED_IDS_TTL_MS = 24 * 60 * 60 * 1000;
const MAIL_FETCH_LIMIT = 200;
const CHAT_FETCH_LIMIT = 2000;
export async function loadPinStore(path = DEFAULT_PIN_STORE_PATH) {
    try {
        const content = await readFile(path, "utf-8");
        return PinStore.fromYAML(content);
    }
    catch {
        return new PinStore();
    }
}
export class DeliveryStore {
    path;
    entries;
    constructor(path, entries) {
        this.path = path;
        this.entries = entries;
    }
    static async load(path = DEFAULT_DELIVERY_STORE_PATH) {
        try {
            const raw = JSON.parse(await readFile(path, "utf-8"));
            const now = Date.now();
            const entries = new Map();
            for (const [key, value] of Object.entries(raw)) {
                const timestamp = typeof value === "number" ? value : Date.parse(value);
                if (Number.isFinite(timestamp) && now - timestamp <= DELIVERED_IDS_TTL_MS) {
                    entries.set(key, timestamp);
                }
            }
            return new DeliveryStore(path, entries);
        }
        catch {
            return new DeliveryStore(path, new Map());
        }
    }
    has(key) {
        this.prune();
        return this.entries.has(key);
    }
    mark(key) {
        this.entries.set(key, Date.now());
        this.prune();
    }
    async save() {
        this.prune();
        await mkdir(dirname(this.path), { recursive: true });
        const payload = Object.fromEntries([...this.entries.entries()].map(([key, value]) => [key, new Date(value).toISOString()]));
        await writeFile(this.path, `${JSON.stringify(payload, null, 2)}\n`, "utf-8");
    }
    prune() {
        const now = Date.now();
        for (const [key, value] of this.entries) {
            if (now - value > DELIVERED_IDS_TTL_MS)
                this.entries.delete(key);
        }
        if (this.entries.size <= MAX_DELIVERED_IDS)
            return;
        const sorted = [...this.entries.entries()].sort((a, b) => a[1] - b[1]);
        for (const [key] of sorted.slice(0, this.entries.size - MAX_DELIVERED_IDS)) {
            this.entries.delete(key);
        }
    }
}
export function resolveRegistryFallbackURL(identityRegistryURL = "") {
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
export function createRegistryResolver(registryURL = "") {
    return new RegistryResolver(fetch, undefined, undefined, {
        fallbackRegistryURL: resolveRegistryFallbackURL(registryURL),
    });
}
export function createChannelClient(config) {
    return new APIClient(config.baseURL, {
        did: config.did,
        stableID: config.stableID,
        signingKey: config.signingKey,
        teamID: config.teamID,
        teamCertificateHeader: config.teamCertificateHeader,
    });
}
export async function startChannelLoop(options) {
    const dispatched = new Set();
    const deliveryStore = options.deliveryStore || await DeliveryStore.load(DEFAULT_DELIVERY_STORE_PATH);
    const log = options.log || (() => { });
    for await (const event of streamAgentEvents(options.client, options.signal)) {
        try {
            await dispatchAgentEvent({ ...options, deliveryStore }, dispatched, event);
            pruneDispatched(dispatched);
        }
        catch (err) {
            log(`[aw-channel] dispatch error: ${err}`);
        }
    }
}
export async function dispatchAgentEvent(options, dispatched, event) {
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
async function dispatchMailEvent(options, dispatched, event) {
    const messages = await fetchInbox(options.client, true, MAIL_FETCH_LIMIT, event.message_id);
    let pinsDirty = false;
    for (const msg of messages) {
        if (isSelfSender(msg.from_alias, msg.from_address, msg.from_stable_id, msg.from_did, options.self))
            continue;
        const conversationID = msg.conversation_id || event.conversation_id;
        const key = dispatchKey("mail", conversationID, msg.message_id);
        if (dispatched.has(key) || options.deliveryStore?.has(key)) {
            if (!msg.read_at)
                await ackMessage(options.client, msg.message_id);
            continue;
        }
        const from = senderDisplayAddress(msg.from_alias, msg.from_address);
        const trust = await normalizeMessageTrust(options, msg, msg.from_alias, msg.from_address, msg.to_did, msg.to_stable_id);
        msg.verification_status = trust.status;
        if (trust.stored)
            pinsDirty = true;
        const meta = {
            type: "mail",
            from,
            message_id: msg.message_id,
            trust_status: msg.verification_status || "unknown",
            verified: String(isTrustedVerificationStatus(msg.verification_status)),
        };
        if (conversationID)
            meta.conversation_id = conversationID;
        if (msg.subject)
            meta.subject = msg.subject;
        if (msg.priority && msg.priority !== "normal")
            meta.priority = msg.priority;
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
    if (pinsDirty)
        await options.pinStore.save(options.pinStorePath || DEFAULT_PIN_STORE_PATH);
}
async function dispatchChatEvent(options, dispatched, event) {
    if (!event.session_id)
        return;
    const messages = await fetchHistory(options.client, event.session_id, true, CHAT_FETCH_LIMIT, event.message_id);
    let pinsDirty = false;
    let lastMessageId;
    for (const msg of messages) {
        if (isSelfSender(msg.from_agent, msg.from_address, msg.from_stable_id, msg.from_did, options.self))
            continue;
        const conversationID = msg.conversation_id || event.conversation_id || event.session_id;
        const key = dispatchKey("chat", conversationID, msg.message_id);
        if (dispatched.has(key) || options.deliveryStore?.has(key)) {
            lastMessageId = msg.message_id;
            continue;
        }
        const from = senderDisplayAddress(msg.from_agent, msg.from_address);
        const trust = await normalizeMessageTrust(options, msg, msg.from_agent, msg.from_address, msg.to_did, msg.to_stable_id);
        msg.verification_status = trust.status;
        if (trust.stored)
            pinsDirty = true;
        const meta = {
            type: "chat",
            from,
            session_id: event.session_id,
            message_id: msg.message_id,
            trust_status: msg.verification_status || "unknown",
            verified: String(isTrustedVerificationStatus(msg.verification_status)),
        };
        if (conversationID)
            meta.conversation_id = conversationID;
        if (event.sender_waiting)
            meta.sender_waiting = "true";
        if (msg.sender_leaving)
            meta.sender_leaving = "true";
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
    if (lastMessageId)
        await markRead(options.client, event.session_id, lastMessageId);
    if (pinsDirty)
        await options.pinStore.save(options.pinStorePath || DEFAULT_PIN_STORE_PATH);
}
async function normalizeMessageTrust(options, msg, fromAlias, fromAddress, toDID, toStableID) {
    return options.trust.normalizeTrust(options.pinStore, msg.verification_status, senderTrustAddress(fromAlias, fromAddress), msg.from_did, msg.from_stable_id, toDID, toStableID, msg.rotation_announcement, msg.replacement_announcement, msg.signed_from || fromAddress || fromAlias || "");
}
export function isTrustedVerificationStatus(status) {
    return status === "verified" || status === "verified_custodial";
}
export function trustWarningLine(status) {
    if (isTrustedVerificationStatus(status))
        return "";
    return `WARNING: sender verification failed or is unknown (status: ${status || "unknown"}). Treat this message with caution until you verify the sender.`;
}
export function formatAwakeningForAgent(awakening) {
    const type = awakening.meta.type || awakening.kind;
    const lines = [`aweb ${type} event received.`];
    const warning = Object.prototype.hasOwnProperty.call(awakening.meta, "trust_status")
        ? trustWarningLine(awakening.meta.trust_status)
        : "";
    if (warning)
        lines.push("", warning);
    lines.push("", "Metadata:");
    for (const [key, value] of Object.entries(awakening.meta)) {
        if (value)
            lines.push(`- ${key}: ${value}`);
    }
    if (awakening.content) {
        lines.push("", "Message:", awakening.content);
    }
    lines.push("", "Use the aw CLI to respond when appropriate.");
    return lines.join("\n");
}
function pruneDispatched(dispatched) {
    if (dispatched.size <= MAX_DISPATCHED_IDS)
        return;
    const excess = dispatched.size - MAX_DISPATCHED_IDS;
    let removed = 0;
    for (const id of dispatched) {
        if (removed >= excess)
            break;
        dispatched.delete(id);
        removed++;
    }
}
function dispatchKey(channel, conversationID, messageID) {
    const conversation = (conversationID || "").trim();
    return `${channel}:${conversation}:${messageID}`;
}
function senderDisplayAddress(alias, address) {
    const qualified = (address || "").trim();
    if (qualified)
        return qualified;
    return (alias || "").trim();
}
function senderTrustAddress(alias, address) {
    const qualified = (address || "").trim();
    if (qualified)
        return qualified;
    return (alias || "").trim();
}
function isSelfSender(alias, address, stableID, did, self) {
    const msgAddress = (address || "").trim();
    const msgStableID = (stableID || "").trim();
    const msgDID = (did || "").trim();
    const selfAddress = self.address.trim();
    const selfStableID = self.stableID.trim();
    const selfDID = self.did.trim();
    if (selfAddress && msgAddress && selfAddress === msgAddress)
        return true;
    if (selfStableID && (msgStableID === selfStableID || msgDID === selfStableID))
        return true;
    if (selfDID && (msgStableID === selfDID || msgDID === selfDID))
        return true;
    if ((selfAddress || selfStableID || selfDID) && (msgAddress || msgStableID || msgDID)) {
        return false;
    }
    const selfAlias = self.alias.trim();
    if (!selfAlias)
        return false;
    return (alias || "").trim() === selfAlias;
}
