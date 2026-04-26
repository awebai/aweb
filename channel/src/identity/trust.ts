import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import type { APIClient } from "../api/client.js";
import type { VerificationStatus } from "./signing.js";
import { extractPublicKey } from "./did.js";
import { RegistryResolver } from "./registry.js";
import { PinStore } from "./pinstore.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const ANNOUNCEMENT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

export interface RotationAnnouncement {
  old_did: string;
  new_did: string;
  timestamp: string;
  old_key_signature: string;
}

export interface ReplacementAnnouncement {
  address: string;
  old_did: string;
  new_did: string;
  controller_did: string;
  timestamp: string;
  controller_signature: string;
}

interface ResolvedIdentity {
  did: string;
  stableID?: string;
  address: string;
  controllerDid?: string;
  custody: string;
  lifetime: string;
}

interface AgentMeta {
  lifetime: string;
  custody: string;
  controllerDid?: string;
  resolved: boolean;
}

export interface TrustResult {
  status: VerificationStatus | undefined;
  stored: boolean;
}

export class SenderTrustManager {
  private readonly metaCache = new Map<string, AgentMeta>();

  constructor(
    private readonly client: APIClient,
    private readonly registry: RegistryResolver,
    private readonly teamID: string,
    private readonly selfDid: string,
    private readonly selfStableID: string = "",
  ) {}

  async normalizeTrust(
    store: PinStore,
    verificationStatus: VerificationStatus | undefined,
    rawAddress: string,
    fromDID: string | undefined,
    fromStableID: string | undefined,
    toDID: string | undefined,
    toStableID: string | undefined,
    rotationAnnouncement?: RotationAnnouncement,
    replacementAnnouncement?: ReplacementAnnouncement,
    verificationAddress?: string,
  ): Promise<TrustResult> {
    let status = this.checkRecipientBinding(verificationStatus, toDID, toStableID);
    if (!status || !rawAddress.trim()) {
      return { status, stored: false };
    }

    const trustAddress = this.canonicalTrustAddress(rawAddress);
    const meta = await this.resolveAgentMeta(rawAddress);
    const registryCheck = await this.checkStableIdentityRegistry(
      status,
      (verificationAddress || rawAddress).trim(),
      fromDID,
      fromStableID,
    );
    status = registryCheck.status;
    return this.checkTOFUPinWithMeta(
      store,
      status,
      rawAddress.trim(),
      trustAddress,
      fromDID,
      fromStableID,
      rotationAnnouncement,
      replacementAnnouncement,
      meta,
      registryCheck.confirmedCurrentKey,
    );
  }

  private checkRecipientBinding(
    status: VerificationStatus | undefined,
    toDID: string | undefined,
    toStableID: string | undefined,
  ): VerificationStatus | undefined {
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
    return recipientDID === selfDID ? status : "identity_mismatch";
  }

  private async checkStableIdentityRegistry(
    status: VerificationStatus | undefined,
    trustAddress: string,
    fromDID: string | undefined,
    fromStableID: string | undefined,
  ): Promise<{ status: VerificationStatus | undefined; confirmedCurrentKey: boolean }> {
    if (status !== "verified" || !fromDID || !fromStableID?.startsWith("did:aw:")) {
      return { status, confirmedCurrentKey: false };
    }

    const registryResult = await this.registry.verifyStableIdentity(trustAddress, fromStableID);
    if (registryResult.outcome === "HARD_ERROR") {
      return { status: "identity_mismatch", confirmedCurrentKey: false };
    }
    if (
      registryResult.outcome === "OK_VERIFIED"
      && registryResult.currentDidKey
      && registryResult.currentDidKey !== fromDID
    ) {
      return { status: "identity_mismatch", confirmedCurrentKey: false };
    }
    return {
      status,
      confirmedCurrentKey: registryResult.outcome === "OK_VERIFIED" && registryResult.currentDidKey === fromDID,
    };
  }

  private checkTOFUPinWithMeta(
    store: PinStore,
    status: VerificationStatus | undefined,
    rawAddress: string,
    trustAddress: string,
    fromDID: string | undefined,
    fromStableID: string | undefined,
    rotationAnnouncement: RotationAnnouncement | undefined,
    replacementAnnouncement: ReplacementAnnouncement | undefined,
    meta: AgentMeta,
    registryConfirmedCurrentKey: boolean,
  ): TrustResult {
    if (
      !status
      || (status !== "verified" && status !== "verified_custodial")
      || !fromDID
      || !trustAddress
      || !meta.resolved
    ) {
      return { status, stored: false };
    }

    if (meta.lifetime === "ephemeral") {
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

    const pinResult = store.checkPin(trustAddress, pinKey, meta.lifetime);
    switch (pinResult) {
      case "new":
        store.storePin(pinKey, trustAddress, "", "");
        if (fromStableID) {
          const pin = store.pins.get(pinKey)!;
          pin.stable_id = fromStableID;
          pin.did_key = fromDID;
        }
        return { status, stored: true };
      case "ok": {
        if (fromStableID) {
          const pin = store.pins.get(pinKey);
          if (pin?.did_key && pin.did_key !== fromDID) {
            // A verified registry chain is authoritative for persistent
            // identities; stale local TOFU must not block archive/recreate.
            // Security assumption: awid enforces a did:aw belongs to one
            // current address; the client does not independently prove that.
            if (registryConfirmedCurrentKey) {
              store.storePin(pinKey, trustAddress, "", "");
              const updated = store.pins.get(pinKey)!;
              updated.stable_id = fromStableID;
              updated.did_key = fromDID;
              return { status, stored: true };
            }
            if (
              !this.verifyRotationAnnouncement(rotationAnnouncement, fromDID, pin.did_key)
              && !this.verifyReplacementAnnouncement(trustAddress, replacementAnnouncement, fromDID, pin.did_key, meta)
            ) {
              return { status: "identity_mismatch", stored: false };
            }
          }
        }
        store.storePin(pinKey, trustAddress, "", "");
        if (fromStableID) {
          const pin = store.pins.get(pinKey)!;
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
          const pin = store.pins.get(pinKey)!;
          pin.stable_id = fromStableID;
          pin.did_key = fromDID;
          return { status, stored: true };
        }
        if (fromStableID && pinnedKey === fromStableID) {
          const pin = store.pins.get(pinnedKey);
          if (pin?.did_key === fromDID) {
            store.storePin(pinnedKey, trustAddress, "", "");
            store.pins.get(pinnedKey)!.stable_id = fromStableID;
            return { status, stored: true };
          }
          if (
            pin?.did_key
            && (
              this.verifyRotationAnnouncement(rotationAnnouncement, fromDID, pin.did_key)
              || this.verifyReplacementAnnouncement(trustAddress, replacementAnnouncement, fromDID, pin.did_key, meta)
            )
          ) {
            store.storePin(pinnedKey, trustAddress, "", "");
            const updated = store.pins.get(pinnedKey)!;
            updated.stable_id = fromStableID;
            updated.did_key = fromDID;
            return { status, stored: true };
          }
        }

        if (
          this.verifyRotationAnnouncement(rotationAnnouncement, fromDID, pinnedKey)
          || this.verifyReplacementAnnouncement(trustAddress, replacementAnnouncement, fromDID, pinnedKey, meta)
        ) {
          if (pinnedKey) {
            store.pins.delete(pinnedKey);
          }
          store.storePin(pinKey, trustAddress, "", "");
          if (fromStableID) {
            const pin = store.pins.get(pinKey)!;
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

  private verifyRotationAnnouncement(
    announcement: RotationAnnouncement | undefined,
    messageDID: string,
    pinnedDID: string,
  ): boolean {
    if (
      !announcement
      || !announcement.old_did
      || !announcement.new_did
      || !announcement.old_key_signature
      || !announcement.timestamp
    ) {
      return false;
    }
    if (!isTimestampFresh(announcement.timestamp)) return false;
    if (announcement.new_did !== messageDID) return false;
    if (announcement.old_did !== pinnedDID) return false;

    try {
      const oldPub = extractPublicKey(announcement.old_did);
      return ed.verify(
        b64Decode(announcement.old_key_signature),
        new TextEncoder().encode(canonicalRotationJSON(announcement.old_did, announcement.new_did, announcement.timestamp)),
        oldPub,
      );
    } catch {
      return false;
    }
  }

  private verifyReplacementAnnouncement(
    address: string,
    announcement: ReplacementAnnouncement | undefined,
    messageDID: string,
    pinnedDID: string,
    meta: AgentMeta,
  ): boolean {
    if (
      !announcement
      || !announcement.address
      || !announcement.old_did
      || !announcement.new_did
      || !announcement.controller_did
      || !announcement.timestamp
      || !announcement.controller_signature
    ) {
      return false;
    }
    if (!isTimestampFresh(announcement.timestamp)) return false;
    if (announcement.address !== address || announcement.new_did !== messageDID || announcement.old_did !== pinnedDID) {
      return false;
    }
    if (!meta.controllerDid || meta.controllerDid !== announcement.controller_did) {
      return false;
    }

    try {
      const controllerPub = extractPublicKey(announcement.controller_did);
      return ed.verify(
        b64Decode(announcement.controller_signature),
        new TextEncoder().encode(
          canonicalReplacementJSON(
            announcement.address,
            announcement.controller_did,
            announcement.old_did,
            announcement.new_did,
            announcement.timestamp,
          ),
        ),
        controllerPub,
      );
    } catch {
      return false;
    }
  }

  private canonicalTrustAddress(address: string): string {
    const trimmed = address.trim();
    if (!trimmed) return "";
    if (trimmed.includes("/") || trimmed.includes("~")) {
      return trimmed;
    }
    return this.teamID ? `${this.teamID}/${trimmed}` : trimmed;
  }

  private async resolveAgentMeta(address: string): Promise<AgentMeta> {
    const rawAddress = address.trim();
    const trustAddress = this.canonicalTrustAddress(rawAddress);
    if (!trustAddress) {
      return { lifetime: "persistent", custody: "self", resolved: false };
    }
    const cached = this.metaCache.get(trustAddress);
    if (cached) return cached;

    try {
      const identity = await this.resolveIdentity(rawAddress);
      const meta: AgentMeta = {
        lifetime: identity.lifetime || "persistent",
        custody: identity.custody || "self",
        controllerDid: identity.controllerDid,
        resolved: true,
      };
      this.metaCache.set(trustAddress, meta);
      return meta;
    } catch {
      return { lifetime: "persistent", custody: "self", resolved: false };
    }
  }

  private async resolveIdentity(address: string): Promise<ResolvedIdentity> {
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

    const response = await this.client.get<{
      did_key?: string;
      did_aw?: string;
      address?: string;
      lifetime?: string;
    }>(
      `/v1/teams/${encodeURIComponent(this.teamID)}/agents/${encodeURIComponent(trimmed)}`,
    );
    return {
      did: response.did_key || "",
      stableID: response.did_aw,
      address: response.address || `${this.teamID}/${trimmed}`,
      custody: "self",
      lifetime: response.lifetime || "ephemeral",
    };
  }
}

function isTimestampFresh(value: string): boolean {
  const time = Date.parse(value);
  if (Number.isNaN(time)) return false;
  return Math.abs(Date.now() - time) <= ANNOUNCEMENT_MAX_AGE_MS;
}

export function canonicalRotationJSON(oldDID: string, newDID: string, timestamp: string): string {
  return canonicalObject([
    ["new_did", newDID],
    ["old_did", oldDID],
    ["timestamp", timestamp],
  ]);
}

export function canonicalReplacementJSON(
  address: string,
  controllerDID: string,
  oldDID: string,
  newDID: string,
  timestamp: string,
): string {
  return canonicalObject([
    ["address", address],
    ["controller_did", controllerDID],
    ["new_did", newDID],
    ["old_did", oldDID],
    ["timestamp", timestamp],
  ]);
}

function canonicalObject(fields: Array<[string, string]>): string {
  const sorted = [...fields].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${sorted.map(([key, value]) => `"${key}":"${escapeJSON(value)}"`).join(",")}}`;
}

function b64Decode(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

function escapeJSON(s: string): string {
  let result = "";
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
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
        } else {
          result += ch;
        }
    }
  }
  return result;
}
