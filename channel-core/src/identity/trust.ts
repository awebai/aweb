import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import type { APIClient } from "../api/client.js";
import type { VerificationStatus } from "./signing.js";
import { extractPublicKey } from "./did.js";
import { RegistryResolver, isValidDidLogSequence, type VerifiedLogHead } from "./registry.js";
import { PinStore, type IdentityScope } from "./pinstore.js";
import { decodeRawStdBase64 } from "./base64.js";

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
  identityScope: IdentityScope;
}

interface LocalAgentResolution {
  alias?: string;
  did_key?: string;
  did_aw?: string;
  address?: string;
  identity_scope?: string;
  lifetime?: string;
}

interface LocalAgentsResponse {
  team_id?: string;
  agents?: LocalAgentResolution[];
}

interface AgentMeta {
  did?: string;
  identityScope: IdentityScope;
  custody: string;
  controllerDid?: string;
  resolved: boolean;
  resolutionError?: "not_found" | "unavailable";
}

export interface TrustResult {
  status: VerificationStatus | undefined;
  stored: boolean;
}

export function normalizeIdentityScope(
  identityScope: string | undefined,
  legacyLifetime: string | undefined,
  defaultScope: IdentityScope,
): IdentityScope {
  const normalizedScope = (identityScope || "").trim().toLowerCase();
  if (normalizedScope === "global" || normalizedScope === "local") return normalizedScope;

  const normalizedLegacy = (legacyLifetime || "").trim().toLowerCase();
  if (normalizedLegacy === "persistent") return "global";
  if (normalizedLegacy === "ephemeral") return "local";

  return defaultScope;
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
    const recipientBindingMismatch = verificationStatus === "verified" && status === "identity_mismatch";
    if (!status || !rawAddress.trim()) {
      return { status, stored: false };
    }

    const trustAddress = this.canonicalTrustAddress(rawAddress);
    if (
      status !== "verified"
      && status !== "verified_legacy"
      && status !== "verified_custodial"
      && this.teamRosterAliasReference(rawAddress.trim()) !== undefined
      && !fromStableID
    ) {
      return { status, stored: false };
    }
    let meta: AgentMeta | undefined;
    if (
      status === "verified"
      && !recipientBindingMismatch
      && this.teamRosterAliasReference(rawAddress.trim()) !== undefined
      && fromDID
    ) {
      const fresh = await this.resolveAgentMeta(rawAddress, true);
      if (!fresh.resolved) {
        return {
          status: fresh.resolutionError === "not_found" ? "identity_mismatch" : "verification_stale",
          stored: false,
        };
      }
      if (fresh.identityScope === "local") {
        return this.verifyResolvedLocalSender(store, rawAddress.trim(), trustAddress, fromDID, fresh);
      }
      if (!fromStableID) {
        return { status: "identity_mismatch", stored: false };
      }
      meta = fresh;
    }
    meta ??= await this.resolveAgentMeta(rawAddress);
    const registryCheck = await this.checkStableIdentityRegistry(
      store,
      status,
      (verificationAddress || rawAddress).trim(),
      fromDID,
      fromStableID,
    );
    status = registryCheck.status;
    const pinResult = this.checkTOFUPinWithMeta(
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
    // Advancing the checkpoint is itself a reason to persist the store. Relying
    // on the pin-write path to have set stored would be coincidental coupling:
    // a refactor of any return path would silently drop rollback protection.
    const checkpointAdvanced = this.persistVerifiedHeadCheckpoint(
      store,
      fromStableID,
      registryCheck.verifiedHead,
    );
    if (
      pinResult.status === "identity_mismatch"
      && !recipientBindingMismatch
      && fromDID
      && this.teamRosterAliasReference(rawAddress.trim()) !== undefined
      && !fromStableID?.startsWith("did:aw:")
    ) {
      return this.verifyLocalSenderAgainstCurrentRoster(store, rawAddress.trim(), trustAddress, fromDID);
    }
    return checkpointAdvanced ? { ...pinResult, stored: true } : pinResult;
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
    if (recipientDID.startsWith("did:aw:")) {
      if (recipientStableID) return status;
      // Legacy shape: stable did:aw was carried in to_did.
      // If we have a self stable_id, treat it as the recipient binding.
      if (selfStableID) {
        return recipientDID.toLowerCase() === selfStableID.toLowerCase() ? status : "identity_mismatch";
      }
      return status;
    }
    return recipientDID === selfDID ? status : "identity_mismatch";
  }

  private async checkStableIdentityRegistry(
    store: PinStore,
    status: VerificationStatus | undefined,
    trustAddress: string,
    fromDID: string | undefined,
    fromStableID: string | undefined,
  ): Promise<{
    status: VerificationStatus | undefined;
    confirmedCurrentKey: boolean;
    verifiedHead?: VerifiedLogHead;
  }> {
    if (status !== "verified" || !fromDID || !fromStableID?.startsWith("did:aw:")) {
      return { status, confirmedCurrentKey: false };
    }

    // Restore the anti-rollback anchor from the checkpoint persisted with the
    // pin. The registry's in-memory head cache is what refuses a sequence
    // regression or a split view, but it is forgotten on restart — so without
    // this a registry can serve a valid truncated prefix and roll a rotated
    // identity back to a retired key (default-aajc.8).
    this.seedVerifiedHeadFromPin(store, fromStableID);
    const registryResult = await this.registry.verifyStableIdentity(trustAddress, fromStableID, fromDID);
    if (registryResult.outcome === "STALE_CACHE") {
      return { status: "verification_stale", confirmedCurrentKey: false };
    }
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
      verifiedHead: registryResult.verifiedHead,
    };
  }

  private seedVerifiedHeadFromPin(store: PinStore, stableID: string): void {
    const seed = (this.registry as { seedVerifiedHead?: (id: string, head: VerifiedLogHead) => void })
      .seedVerifiedHead;
    if (typeof seed !== "function") return;
    const pin = store.pins.get(stableID);
    if (!pin?.log_seq || !pin.log_entry_hash) return;
    seed.call(this.registry, stableID, {
      seq: pin.log_seq,
      entryHash: pin.log_entry_hash,
      stateHash: "",
      currentDidKey: pin.did_key ?? "",
      fetchedAt: 0,
    });
  }

  /**
   * Record the verified head with the pin so the anchor survives a restart. Only
   * ever advances, so a stale response cannot weaken the checkpoint. Called
   * after the pin check because on first contact the pin does not exist until
   * that check runs.
   */
  private persistVerifiedHeadCheckpoint(
    store: PinStore,
    stableID: string | undefined,
    head: VerifiedLogHead | undefined,
  ): boolean {
    if (!stableID || !head || !isValidDidLogSequence(head.seq) || !head.entryHash.trim()) return false;
    return store.advanceLogCheckpoint(stableID, head.seq, head.entryHash);
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

    if (meta.identityScope === "local") {
      return {
        status,
        stored: store.removeAddresses([trustAddress, rawAddress !== trustAddress ? rawAddress : ""]),
      };
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
        const rekey = store.bindStableIdentity(fromDID, fromStableID);
        if (rekey.status === "conflict") {
          // A stable id is one key and a pin carries one address, so an
          // identity already pinned at another address cannot also move onto
          // that key here. Keep both pins and stay on the did:key for this
          // address, so the check below is made against the key the reverse
          // index actually holds. Failing the message instead would report a
          // legitimate sender as untrusted for being reachable twice.
          pinKey = fromDID;
        }
      }
    }

    const pinResult = store.checkPin(trustAddress, pinKey, meta.identityScope);
    switch (pinResult) {
      case "new":
        store.recordVerifiedIdentity(pinKey, trustAddress, fromStableID, fromDID);
        return { status, stored: true };
      case "ok": {
        if (fromStableID) {
          const pin = store.pins.get(pinKey);
          if (pin?.did_key && pin.did_key !== fromDID) {
            // Same stable identity, different did:key: this is key rotation,
            // which the DID log DOES prove (did:aw -> did:key), so a verified
            // registry chain is sufficient here. It says nothing about address
            // ownership — that is enforced in the mismatch branch below.
            if (registryConfirmedCurrentKey) {
              store.recordVerifiedIdentity(pinKey, trustAddress, fromStableID, fromDID);
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
        store.recordVerifiedIdentity(pinKey, trustAddress, fromStableID, fromDID);
        return { status, stored: true };
      }
      case "mismatch": {
        const pinnedKey = store.addresses.get(trustAddress) || "";
        // A verified DID log proves did:aw -> did:key. It proves NOTHING about
        // which address that identity may claim, so it is not authority to take
        // over an address pinned to a different stable identity: an attacker who
        // legitimately owns did:aw:attacker can have a wholly valid log. Only the
        // address authority can authorize the transfer, via a replacement
        // announcement signed by the namespace controller named in the address's
        // _awid DNS TXT record. Absent that proof the pin stands and the mismatch
        // is reported (default-aajc.8).
        if (fromStableID && pinnedKey === fromStableID) {
          const pin = store.pins.get(pinnedKey);
          if (pin?.did_key === fromDID) {
            store.recordVerifiedIdentity(pinnedKey, trustAddress, fromStableID);
            return { status, stored: true };
          }
          if (
            pin?.did_key
            && (
              this.verifyRotationAnnouncement(rotationAnnouncement, fromDID, pin.did_key)
              || this.verifyReplacementAnnouncement(trustAddress, replacementAnnouncement, fromDID, pin.did_key, meta)
            )
          ) {
            store.recordVerifiedIdentity(pinnedKey, trustAddress, fromStableID, fromDID);
            return { status, stored: true };
          }
        }

        if (
          this.verifyRotationAnnouncement(rotationAnnouncement, fromDID, pinnedKey)
          || this.verifyReplacementAnnouncement(trustAddress, replacementAnnouncement, fromDID, pinnedKey, meta)
        ) {
          store.replaceVerifiedIdentity(pinnedKey, pinKey, trustAddress, fromStableID, fromDID);
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

  private async verifyLocalSenderAgainstCurrentRoster(
    store: PinStore,
    rawAddress: string,
    trustAddress: string,
    fromDID: string,
  ): Promise<TrustResult> {
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
    return this.verifyResolvedLocalSender(store, rawAddress, trustAddress, fromDID, fresh);
  }

  private verifyResolvedLocalSender(
    store: PinStore,
    rawAddress: string,
    trustAddress: string,
    fromDID: string,
    fresh: AgentMeta,
  ): TrustResult {
    if (!fresh.did) {
      return { status: "verification_stale", stored: false };
    }
    if (fresh.did !== fromDID) {
      return { status: "identity_mismatch", stored: false };
    }
    const removed = store.removeAddresses([
      trustAddress,
      rawAddress !== trustAddress ? rawAddress : "",
    ]);
    return { status: "verified", stored: removed };
  }

  private async resolveAgentMeta(address: string, forceRefresh: boolean = false): Promise<AgentMeta> {
    const rawAddress = address.trim();
    const trustAddress = this.canonicalTrustAddress(rawAddress);
    if (!trustAddress) {
      return { identityScope: "global", custody: "self", resolved: false };
    }
    const cached = this.metaCache.get(trustAddress);
    if (!forceRefresh && cached) return cached;

    try {
      const identity = await this.resolveIdentity(rawAddress, forceRefresh);
      const meta: AgentMeta = {
        did: identity.did,
        identityScope: identity.identityScope,
        custody: identity.custody || "self",
        controllerDid: identity.controllerDid,
        resolved: true,
      };
      this.metaCache.set(trustAddress, meta);
      return meta;
    } catch (error) {
      const statusCode = (error as { statusCode?: unknown } | undefined)?.statusCode;
      return {
        identityScope: "global",
        custody: "self",
        resolved: false,
        resolutionError: statusCode === 404 ? "not_found" : "unavailable",
      };
    }
  }

  private teamRosterAliasReference(address: string): string | undefined {
    const client = this.client as APIClient & { hasTeamCertificateAuth?: (teamID: string) => boolean };
    return teamRosterAliasReference(
      address,
      this.teamID,
      typeof client.hasTeamCertificateAuth === "function",
    );
  }

  private async resolveIdentity(address: string, forceRefresh: boolean = false): Promise<ResolvedIdentity> {
    const trimmed = address.trim();
    if (!trimmed) {
      throw new Error("missing address");
    }
    const localAlias = this.teamRosterAliasReference(trimmed);
    if (localAlias === undefined) {
      if (trimmed.includes("/")) {
        return this.registry.resolveIdentity(trimmed);
      }
      throw new Error(`unsupported local address ${trimmed}`);
    }
    if (!this.client.hasTeamCertificateAuth(this.teamID)) {
      throw new Error("team roster resolution requires team-certificate authentication");
    }

    const path = "/v1/agents";
    const roster = forceRefresh
      ? await this.client.getFresh<LocalAgentsResponse>(path)
      : await this.client.get<LocalAgentsResponse>(path);
    if ((roster.team_id || "").trim() !== this.teamID) {
      throw new Error("team roster response does not match the authenticated team");
    }
    const response = (roster.agents || []).find((agent) => (agent.alias || "").trim() === localAlias);
    if (!response) {
      const qualifiedTeamPrefix = `${this.teamID.toLowerCase()}/`;
      if (trimmed.includes("/") && !trimmed.toLowerCase().startsWith(qualifiedTeamPrefix)) {
        return this.registry.resolveIdentity(trimmed);
      }
      throw Object.assign(new Error(`local alias ${localAlias} is absent from the authenticated team roster`), {
        statusCode: 404,
      });
    }
    const did = (response.did_key || "").trim();
    if (did) {
      extractPublicKey(did);
    }
    return {
      did,
      stableID: response.did_aw,
      address: response.address || `${this.teamID}/${localAlias}`,
      custody: "self",
      identityScope: normalizeIdentityScope(response.identity_scope, response.lifetime, "local"),
    };
  }
}

function teamRosterAliasReference(value: string, teamID: string, includeProjectedAddress: boolean): string | undefined {
  const trimmed = value.trim();
  const configuredTeamID = teamID.trim();
  if (!trimmed || !configuredTeamID || trimmed.includes("~") || trimmed.startsWith("did:")) return undefined;
  if (!trimmed.includes("/")) return trimmed;
  const separator = trimmed.indexOf("/");
  if (separator <= 0 || trimmed.indexOf("/", separator + 1) !== -1) return undefined;
  const qualifier = trimmed.slice(0, separator).trim().toLowerCase();
  const alias = trimmed.slice(separator + 1).trim();
  if (!alias) return undefined;
  const namespace = configuredTeamID.split(":", 2)[1]?.trim().toLowerCase();
  if (qualifier !== configuredTeamID.toLowerCase() && (!includeProjectedAddress || qualifier !== namespace)) return undefined;
  return alias;
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
  // Rotation and replacement announcements are remote signed data. Throw on
  // malformed raw base64 before ed.verify so rejection does not depend on how
  // the verifier treats an empty signature.
  return decodeRawStdBase64(value);
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
