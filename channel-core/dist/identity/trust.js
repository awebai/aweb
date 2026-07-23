import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { extractPublicKey } from "./did.js";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
const ANNOUNCEMENT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export function normalizeIdentityScope(identityScope, legacyLifetime, defaultScope) {
    const normalizedScope = (identityScope || "").trim().toLowerCase();
    if (normalizedScope === "global" || normalizedScope === "local")
        return normalizedScope;
    const normalizedLegacy = (legacyLifetime || "").trim().toLowerCase();
    if (normalizedLegacy === "persistent")
        return "global";
    if (normalizedLegacy === "ephemeral")
        return "local";
    return defaultScope;
}
export class SenderTrustManager {
    client;
    registry;
    teamID;
    selfDid;
    selfStableID;
    metaCache = new Map();
    constructor(client, registry, teamID, selfDid, selfStableID = "") {
        this.client = client;
        this.registry = registry;
        this.teamID = teamID;
        this.selfDid = selfDid;
        this.selfStableID = selfStableID;
    }
    async normalizeTrust(store, verificationStatus, rawAddress, fromDID, fromStableID, toDID, toStableID, rotationAnnouncement, replacementAnnouncement, verificationAddress) {
        let status = this.checkRecipientBinding(verificationStatus, toDID, toStableID);
        const recipientBindingMismatch = verificationStatus === "verified" && status === "identity_mismatch";
        if (!status || !rawAddress.trim()) {
            return { status, stored: false };
        }
        const trustAddress = this.canonicalTrustAddress(rawAddress);
        const meta = await this.resolveAgentMeta(rawAddress);
        const registryCheck = await this.checkStableIdentityRegistry(status, (verificationAddress || rawAddress).trim(), fromDID, fromStableID);
        status = registryCheck.status;
        const pinResult = this.checkTOFUPinWithMeta(store, status, rawAddress.trim(), trustAddress, fromDID, fromStableID, rotationAnnouncement, replacementAnnouncement, meta, registryCheck.confirmedCurrentKey);
        if (pinResult.status === "identity_mismatch"
            && !recipientBindingMismatch
            && fromDID
            && isLocalAliasReference(rawAddress.trim())
            && !fromStableID?.startsWith("did:aw:")) {
            return this.reconcileLocalMismatch(store, rawAddress.trim(), trustAddress, fromDID);
        }
        return pinResult;
    }
    checkRecipientBinding(status, toDID, toStableID) {
        if (status !== "verified") {
            return status;
        }
        const selfStableID = this.selfStableID.trim();
        const recipientStableID = (toStableID || "").trim();
        if (selfStableID && recipientStableID) {
            return recipientStableID.toLowerCase() === selfStableID.toLowerCase()
                ? status
                : "identity_mismatch";
        }
        const selfDID = this.selfDid.trim();
        const recipientDID = (toDID || "").trim();
        if (!recipientDID || !selfDID) {
            return status;
        }
        if (recipientDID.startsWith("did:aw:")) {
            if (recipientStableID)
                return status;
            // Legacy shape: stable did:aw was carried in to_did.
            // If we have a self stable_id, treat it as the recipient binding.
            if (selfStableID) {
                return recipientDID.toLowerCase() === selfStableID.toLowerCase() ? status : "identity_mismatch";
            }
            return status;
        }
        return recipientDID === selfDID ? status : "identity_mismatch";
    }
    async checkStableIdentityRegistry(status, trustAddress, fromDID, fromStableID) {
        if (status !== "verified" || !fromDID || !fromStableID?.startsWith("did:aw:")) {
            return { status, confirmedCurrentKey: false };
        }
        const registryResult = await this.registry.verifyStableIdentity(trustAddress, fromStableID, fromDID);
        if (registryResult.outcome === "STALE_CACHE") {
            return { status: "verification_stale", confirmedCurrentKey: false };
        }
        if (registryResult.outcome === "HARD_ERROR") {
            return { status: "identity_mismatch", confirmedCurrentKey: false };
        }
        if (registryResult.outcome === "OK_VERIFIED"
            && registryResult.currentDidKey
            && registryResult.currentDidKey !== fromDID) {
            return { status: "identity_mismatch", confirmedCurrentKey: false };
        }
        return {
            status,
            confirmedCurrentKey: registryResult.outcome === "OK_VERIFIED" && registryResult.currentDidKey === fromDID,
        };
    }
    checkTOFUPinWithMeta(store, status, rawAddress, trustAddress, fromDID, fromStableID, rotationAnnouncement, replacementAnnouncement, meta, registryConfirmedCurrentKey) {
        if (!status
            || (status !== "verified" && status !== "verified_custodial")
            || !fromDID
            || !trustAddress
            || !meta.resolved) {
            return { status, stored: false };
        }
        if (meta.identityScope === "local") {
            let removed = store.removeAddress(trustAddress);
            if (rawAddress && rawAddress !== trustAddress) {
                removed = store.removeAddress(rawAddress) || removed;
            }
            return { status, stored: removed };
        }
        if (meta.custody === "custodial" && status === "verified") {
            status = "verified_custodial";
        }
        if (fromStableID && !fromStableID.startsWith("did:aw:")) {
            fromStableID = undefined;
        }
        let pinKey = fromDID;
        if (fromStableID) {
            pinKey = fromStableID;
            const existingDID = store.addresses.get(trustAddress);
            if (existingDID === fromDID) {
                const existingPin = store.pins.get(fromDID);
                if (existingPin) {
                    store.pins.delete(fromDID);
                    existingPin.stable_id = fromStableID;
                    store.pins.set(fromStableID, existingPin);
                    store.addresses.set(trustAddress, fromStableID);
                }
            }
        }
        const pinResult = store.checkPin(trustAddress, pinKey, meta.identityScope);
        switch (pinResult) {
            case "new":
                store.storePin(pinKey, trustAddress, "", "");
                if (fromStableID) {
                    const pin = store.pins.get(pinKey);
                    pin.stable_id = fromStableID;
                    pin.did_key = fromDID;
                }
                return { status, stored: true };
            case "ok": {
                if (fromStableID) {
                    const pin = store.pins.get(pinKey);
                    if (pin?.did_key && pin.did_key !== fromDID) {
                        // A verified registry chain is authoritative for global identities;
                        // stale local TOFU must not block archive/recreate.
                        // Security assumption: awid enforces a did:aw belongs to one
                        // current address; the client does not independently prove that.
                        if (registryConfirmedCurrentKey) {
                            store.storePin(pinKey, trustAddress, "", "");
                            const updated = store.pins.get(pinKey);
                            updated.stable_id = fromStableID;
                            updated.did_key = fromDID;
                            return { status, stored: true };
                        }
                        if (!this.verifyRotationAnnouncement(rotationAnnouncement, fromDID, pin.did_key)
                            && !this.verifyReplacementAnnouncement(trustAddress, replacementAnnouncement, fromDID, pin.did_key, meta)) {
                            return { status: "identity_mismatch", stored: false };
                        }
                    }
                }
                store.storePin(pinKey, trustAddress, "", "");
                if (fromStableID) {
                    const pin = store.pins.get(pinKey);
                    pin.stable_id = fromStableID;
                    pin.did_key = fromDID;
                }
                return { status, stored: true };
            }
            case "mismatch": {
                const pinnedKey = store.addresses.get(trustAddress) || "";
                // A verified registry chain proves the address now belongs to this
                // stable identity and did:key, so replace the stale address pin.
                // Security assumption: awid enforces a did:aw belongs to one current
                // address; the client does not independently prove that.
                if (registryConfirmedCurrentKey && fromStableID) {
                    store.removeAddress(trustAddress);
                    store.storePin(pinKey, trustAddress, "", "");
                    const pin = store.pins.get(pinKey);
                    pin.stable_id = fromStableID;
                    pin.did_key = fromDID;
                    return { status, stored: true };
                }
                if (fromStableID && pinnedKey === fromStableID) {
                    const pin = store.pins.get(pinnedKey);
                    if (pin?.did_key === fromDID) {
                        store.storePin(pinnedKey, trustAddress, "", "");
                        store.pins.get(pinnedKey).stable_id = fromStableID;
                        return { status, stored: true };
                    }
                    if (pin?.did_key
                        && (this.verifyRotationAnnouncement(rotationAnnouncement, fromDID, pin.did_key)
                            || this.verifyReplacementAnnouncement(trustAddress, replacementAnnouncement, fromDID, pin.did_key, meta))) {
                        store.storePin(pinnedKey, trustAddress, "", "");
                        const updated = store.pins.get(pinnedKey);
                        updated.stable_id = fromStableID;
                        updated.did_key = fromDID;
                        return { status, stored: true };
                    }
                }
                if (this.verifyRotationAnnouncement(rotationAnnouncement, fromDID, pinnedKey)
                    || this.verifyReplacementAnnouncement(trustAddress, replacementAnnouncement, fromDID, pinnedKey, meta)) {
                    if (pinnedKey) {
                        store.pins.delete(pinnedKey);
                    }
                    store.storePin(pinKey, trustAddress, "", "");
                    if (fromStableID) {
                        const pin = store.pins.get(pinKey);
                        pin.stable_id = fromStableID;
                        pin.did_key = fromDID;
                    }
                    return { status, stored: true };
                }
                return { status: "identity_mismatch", stored: false };
            }
            case "skipped":
                return { status, stored: false };
        }
    }
    verifyRotationAnnouncement(announcement, messageDID, pinnedDID) {
        if (!announcement
            || !announcement.old_did
            || !announcement.new_did
            || !announcement.old_key_signature
            || !announcement.timestamp) {
            return false;
        }
        if (!isTimestampFresh(announcement.timestamp))
            return false;
        if (announcement.new_did !== messageDID)
            return false;
        if (announcement.old_did !== pinnedDID)
            return false;
        try {
            const oldPub = extractPublicKey(announcement.old_did);
            return ed.verify(b64Decode(announcement.old_key_signature), new TextEncoder().encode(canonicalRotationJSON(announcement.old_did, announcement.new_did, announcement.timestamp)), oldPub);
        }
        catch {
            return false;
        }
    }
    verifyReplacementAnnouncement(address, announcement, messageDID, pinnedDID, meta) {
        if (!announcement
            || !announcement.address
            || !announcement.old_did
            || !announcement.new_did
            || !announcement.controller_did
            || !announcement.timestamp
            || !announcement.controller_signature) {
            return false;
        }
        if (!isTimestampFresh(announcement.timestamp))
            return false;
        if (announcement.address !== address || announcement.new_did !== messageDID || announcement.old_did !== pinnedDID) {
            return false;
        }
        if (!meta.controllerDid || meta.controllerDid !== announcement.controller_did) {
            return false;
        }
        try {
            const controllerPub = extractPublicKey(announcement.controller_did);
            return ed.verify(b64Decode(announcement.controller_signature), new TextEncoder().encode(canonicalReplacementJSON(announcement.address, announcement.controller_did, announcement.old_did, announcement.new_did, announcement.timestamp)), controllerPub);
        }
        catch {
            return false;
        }
    }
    canonicalTrustAddress(address) {
        const trimmed = address.trim();
        if (!trimmed)
            return "";
        if (trimmed.includes("/") || trimmed.includes("~")) {
            return trimmed;
        }
        return this.teamID ? `${this.teamID}/${trimmed}` : trimmed;
    }
    async reconcileLocalMismatch(store, rawAddress, trustAddress, fromDID) {
        const fresh = await this.resolveAgentMeta(rawAddress, true);
        if (!fresh.resolved) {
            return {
                status: fresh.resolutionError === "not_found" ? "identity_mismatch" : "verification_stale",
                stored: false,
            };
        }
        if (fresh.identityScope !== "local") {
            return { status: "identity_mismatch", stored: false };
        }
        if (!fresh.did) {
            return { status: "verification_stale", stored: false };
        }
        if (fresh.did !== fromDID) {
            return { status: "identity_mismatch", stored: false };
        }
        let removed = store.removeAddress(trustAddress);
        if (rawAddress && rawAddress !== trustAddress) {
            removed = store.removeAddress(rawAddress) || removed;
        }
        return { status: "verification_stale", stored: removed };
    }
    async resolveAgentMeta(address, forceRefresh = false) {
        const rawAddress = address.trim();
        const trustAddress = this.canonicalTrustAddress(rawAddress);
        if (!trustAddress) {
            return { identityScope: "global", custody: "self", resolved: false };
        }
        const cached = this.metaCache.get(trustAddress);
        if (!forceRefresh && cached)
            return cached;
        try {
            const identity = await this.resolveIdentity(rawAddress, forceRefresh);
            const meta = {
                did: identity.did,
                identityScope: identity.identityScope,
                custody: identity.custody || "self",
                controllerDid: identity.controllerDid,
                resolved: true,
            };
            this.metaCache.set(trustAddress, meta);
            return meta;
        }
        catch (error) {
            const statusCode = error?.statusCode;
            return {
                identityScope: "global",
                custody: "self",
                resolved: false,
                resolutionError: statusCode === 404 ? "not_found" : "unavailable",
            };
        }
    }
    async resolveIdentity(address, forceRefresh = false) {
        const trimmed = address.trim();
        if (!trimmed) {
            throw new Error("missing address");
        }
        if (trimmed.includes("/")) {
            return this.registry.resolveIdentity(trimmed);
        }
        if (trimmed.includes("~") || !this.teamID) {
            throw new Error(`unsupported local address ${trimmed}`);
        }
        const path = `/v1/teams/${encodeURIComponent(this.teamID)}/agents/${encodeURIComponent(trimmed)}`;
        const response = forceRefresh
            ? await this.client.getFresh(path)
            : await this.client.get(path);
        return {
            did: response.did_key || "",
            stableID: response.did_aw,
            address: response.address || `${this.teamID}/${trimmed}`,
            custody: "self",
            identityScope: normalizeIdentityScope(response.identity_scope, response.lifetime, "local"),
        };
    }
}
function isLocalAliasReference(value) {
    return value !== "" && !value.includes("/") && !value.includes("~") && !value.startsWith("did:");
}
function isTimestampFresh(value) {
    const time = Date.parse(value);
    if (Number.isNaN(time))
        return false;
    return Math.abs(Date.now() - time) <= ANNOUNCEMENT_MAX_AGE_MS;
}
export function canonicalRotationJSON(oldDID, newDID, timestamp) {
    return canonicalObject([
        ["new_did", newDID],
        ["old_did", oldDID],
        ["timestamp", timestamp],
    ]);
}
export function canonicalReplacementJSON(address, controllerDID, oldDID, newDID, timestamp) {
    return canonicalObject([
        ["address", address],
        ["controller_did", controllerDID],
        ["new_did", newDID],
        ["old_did", oldDID],
        ["timestamp", timestamp],
    ]);
}
function canonicalObject(fields) {
    const sorted = [...fields].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${sorted.map(([key, value]) => `"${key}":"${escapeJSON(value)}"`).join(",")}}`;
}
function b64Decode(value) {
    return Uint8Array.from(Buffer.from(value, "base64"));
}
function escapeJSON(s) {
    let result = "";
    for (const ch of s) {
        const code = ch.codePointAt(0);
        switch (ch) {
            case "\"":
                result += "\\\"";
                break;
            case "\\":
                result += "\\\\";
                break;
            case "\n":
                result += "\\n";
                break;
            case "\r":
                result += "\\r";
                break;
            case "\t":
                result += "\\t";
                break;
            case "\b":
                result += "\\b";
                break;
            case "\f":
                result += "\\f";
                break;
            default:
                if (code < 0x20) {
                    result += `\\u${code.toString(16).padStart(4, "0")}`;
                }
                else {
                    result += ch;
                }
        }
    }
    return result;
}
