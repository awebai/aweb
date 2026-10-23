import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import type { APIClient } from "../api/client.js";
import type { VerificationStatus } from "./signing.js";
import { extractPublicKey } from "./did.js";
import {
  RegistryResolver,
  isValidDidLogSequence,
  type StableIdentityVerification,
  type VerifiedLogHead,
} from "./registry.js";
import { PinStore, type IdentityScope } from "./pinstore.js";
import { decodeRawStdBase64 } from "./base64.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const ANNOUNCEMENT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const AGENT_META_CACHE_TTL_MS = 60 * 60 * 1000;
const AGENT_META_FAILURE_CACHE_MIN_MS = 30_000;
const AGENT_META_FAILURE_CACHE_JITTER_MS = 30_000;
const TEAM_ROSTER_CACHE_TTL_MS = 60_000;
const TEAM_ROSTER_FAILURE_BACKOFF_MIN_MS = 10_000;
const TEAM_ROSTER_FAILURE_BACKOFF_JITTER_MS = 20_000;

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

interface PinCheckpoint {
  seq: number;
  entryHash: string;
}

interface PreparedStableIdentityCheck {
  checkpoint: PinCheckpoint | undefined;
  result: StableIdentityVerification;
}

export interface SenderAdmission {
  outcome: "verified" | "verified_legacy" | "unverified" | "failed" | "unrecorded" | "unknown";
  message_id?: string | null;
  did_key?: string | null;
  team_id?: string | null;
  certificate_id?: string | null;
  did_aw?: string | null;
  address?: string | null;
}

export interface SenderMembership {
  team_id: string;
  member_did_aw?: string | null;
  state: "active" | "inactive" | "unknown";
  current_status?: "active" | "retired" | "revoked" | "unknown";
  admission?: SenderAdmission | null;
}

interface ReceivedSenderCheck {
  fromDID: string;
  stableID: string;
  status: VerificationStatus;
  registryURL?: string;
  checkpoint?: PinCheckpoint;
  head?: VerifiedLogHead;
}

interface ResolvedTrustMetadata {
  trustAddress: string;
  meta: AgentMeta;
  stableIdentityCheck?: PreparedStableIdentityCheck;
  receivedSender?: ReceivedSenderCheck;
  receivedLocalSender?: { did: string; status: VerificationStatus };
  admittedSender?: { did: string; stableID: string; status: VerificationStatus | undefined };
}

interface ResolveTrustContext {
  pinStore: PinStore;
  fromDID: string | undefined;
  verificationAddress: string;
  senderAddress?: string;
  senderMembership?: SenderMembership;
  senderTeamID?: string;
  projectedSenderDID?: string;
  messageID?: string;
}

interface AgentMetaCacheEntry {
  meta: AgentMeta;
  expiresAt: number;
}

type TeamRosterCacheEntry =
  | { roster: LocalAgentsResponse; expiresAt: number }
  | { error: unknown; expiresAt: number };

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
  private readonly metaCache = new Map<string, AgentMetaCacheEntry>();
  private readonly preparedMetadata = new WeakSet<ResolvedTrustMetadata>();
  private readonly localMismatchRefreshAfter = new Map<string, number>();
  private teamRosterCache: TeamRosterCacheEntry | undefined;
  private teamRosterRequest: Promise<LocalAgentsResponse> | undefined;

  constructor(
    private readonly client: APIClient,
    private readonly registry: RegistryResolver,
    private readonly teamID: string,
    private readonly selfDid: string,
    private readonly selfStableID: string = "",
    private readonly now: () => number = () => Date.now(),
    private readonly random: () => number = () => Math.random(),
  ) {}

  async resolveTrustMetadata(
    verificationStatus: VerificationStatus | undefined,
    rawAddress: string,
    fromStableID: string | undefined,
    toDID: string | undefined,
    toStableID: string | undefined,
    context?: ResolveTrustContext,
  ): Promise<ResolvedTrustMetadata | undefined> {
    const status = this.checkRecipientBinding(verificationStatus, toDID, toStableID);
    const trimmedAddress = rawAddress.trim();
    if (context?.senderMembership?.admission) {
      const resolved: ResolvedTrustMetadata = {
        trustAddress: this.canonicalTrustAddress(trimmedAddress), meta: this.unavailableAgentMeta(),
        admittedSender: { did: context.fromDID || "", stableID: fromStableID || "",
          status: this.admittedSenderTrust(status, fromStableID, context) },
      };
      this.preparedMetadata.add(resolved);
      return resolved;
    }
    const local = context && !fromStableID && this.prepareReceivedLocalSender(status, context);
    if (local) {
      const resolved: ResolvedTrustMetadata = {
        trustAddress: this.canonicalTrustAddress(trimmedAddress), meta: this.unavailableAgentMeta(),
        receivedLocalSender: local,
      };
      this.preparedMetadata.add(resolved);
      return resolved;
    }
    if (context && context.senderAddress === "" && fromStableID?.startsWith("did:aw:")) {
      const resolved: ResolvedTrustMetadata = {
        trustAddress: this.canonicalTrustAddress(trimmedAddress),
        meta: this.unavailableAgentMeta(),
        receivedSender: await this.prepareReceivedSender(status, fromStableID, context),
      };
      this.preparedMetadata.add(resolved);
      return resolved;
    }
    if (!status || !trimmedAddress) return undefined;
    if (
      context
      && !context.fromDID
      && (status === "verified" || status === "verified_legacy" || status === "verified_custodial")
    ) {
      return undefined;
    }
    const rosterAlias = this.teamRosterAliasReference(trimmedAddress);
    if (
      status !== "verified"
      && status !== "verified_legacy"
      && status !== "verified_custodial"
      && rosterAlias !== undefined
      && !fromStableID
    ) {
      return undefined;
    }
    const trustAddress = this.canonicalTrustAddress(trimmedAddress);
    const cachedMeta = this.metaCache.get(trustAddress);
    const cachedRoster = this.teamRosterCache;
    const usedCachedMetadata = (cachedMeta && this.now() <= cachedMeta.expiresAt)
      || (cachedRoster && "roster" in cachedRoster && this.now() <= cachedRoster.expiresAt);
    let meta = await this.resolveAgentMeta(trimmedAddress);
    const localKeyMismatch = meta.resolved && meta.identityScope === "local"
      && meta.did && meta.did !== context?.fromDID;
    const cachedAbsence = !meta.resolved && meta.resolutionError === "not_found";
    if (
      usedCachedMetadata
      && rosterAlias !== undefined
      && (status === "verified" || status === "verified_legacy" || status === "verified_custodial")
      && context?.fromDID
      && !fromStableID?.startsWith("did:aw:")
      && (localKeyMismatch || cachedAbsence)
      && this.now() >= (this.localMismatchRefreshAfter.get(trustAddress) ?? 0)
    ) {
      // Resolve before the pin lock. Local aliases follow the authenticated
      // roster, not global TOFU continuity. A cached absence can predate a new
      // member. Concurrent refreshes share the roster request; repeated
      // non-member keys get a short quiet interval.
      meta = await this.resolveAgentMeta(trimmedAddress, true);
      if (meta.resolved && meta.identityScope === "local" && meta.did === context.fromDID) {
        // The matching row is cached. Let a subsequent authorized transition
        // refresh immediately, including re-init just after a member joins.
        this.localMismatchRefreshAfter.delete(trustAddress);
      } else {
        this.localMismatchRefreshAfter.set(trustAddress, this.now() + this.jitteredTTL(
          TEAM_ROSTER_FAILURE_BACKOFF_MIN_MS,
          TEAM_ROSTER_FAILURE_BACKOFF_JITTER_MS,
        ));
      }
    }
    const stableIdentityCheck = context && meta.resolved && meta.identityScope !== "local"
      ? await this.prepareStableIdentityRegistry(
        context.pinStore,
        status,
        context.verificationAddress,
        context.fromDID,
        fromStableID,
      )
      : undefined;
    const resolved = { trustAddress, meta, stableIdentityCheck };
    this.preparedMetadata.add(resolved);
    return resolved;
  }

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
    resolvedMetadata?: ResolvedTrustMetadata,
  ): Promise<TrustResult> {
    let resolved = this.consumeResolvedMetadata(rawAddress, resolvedMetadata);
    if (
      resolved
      && this.requiresStableIdentityCheck(
        this.checkRecipientBinding(verificationStatus, toDID, toStableID),
        fromDID,
        fromStableID,
      )
      && resolved.meta.identityScope !== "local"
      && !resolved.stableIdentityCheck
      && !resolved.receivedSender
      && !resolved.admittedSender
    ) {
      resolved = undefined;
    }
    if (!resolved) {
      const prepared = await this.resolveTrustMetadata(
        verificationStatus,
        rawAddress,
        fromStableID,
        toDID,
        toStableID,
        {
          pinStore: store,
          fromDID,
          verificationAddress: (verificationAddress || rawAddress).trim(),
        },
      );
      resolved = this.consumeResolvedMetadata(rawAddress, prepared);
    }
    return this.normalizeTrustDecision(
      store,
      verificationStatus,
      rawAddress,
      fromDID,
      fromStableID,
      toDID,
      toStableID,
      rotationAnnouncement,
      replacementAnnouncement,
      resolved,
    );
  }

  async normalizeResolvedTrust(
    store: PinStore,
    verificationStatus: VerificationStatus | undefined,
    rawAddress: string,
    fromDID: string | undefined,
    fromStableID: string | undefined,
    toDID: string | undefined,
    toStableID: string | undefined,
    rotationAnnouncement?: RotationAnnouncement,
    replacementAnnouncement?: ReplacementAnnouncement,
    _verificationAddress?: string,
    resolvedMetadata?: ResolvedTrustMetadata,
  ): Promise<TrustResult> {
    return this.normalizeTrustDecision(
      store,
      verificationStatus,
      rawAddress,
      fromDID,
      fromStableID,
      toDID,
      toStableID,
      rotationAnnouncement,
      replacementAnnouncement,
      this.consumeResolvedMetadata(rawAddress, resolvedMetadata),
    );
  }

  private consumeResolvedMetadata(
    rawAddress: string,
    resolvedMetadata: ResolvedTrustMetadata | undefined,
  ): ResolvedTrustMetadata | undefined {
    if (!resolvedMetadata || !this.preparedMetadata.delete(resolvedMetadata)) return undefined;
    return resolvedMetadata.trustAddress === this.canonicalTrustAddress(rawAddress)
      ? resolvedMetadata
      : undefined;
  }

  private normalizeTrustDecision(
    store: PinStore,
    verificationStatus: VerificationStatus | undefined,
    rawAddress: string,
    fromDID: string | undefined,
    fromStableID: string | undefined,
    toDID: string | undefined,
    toStableID: string | undefined,
    rotationAnnouncement: RotationAnnouncement | undefined,
    replacementAnnouncement: ReplacementAnnouncement | undefined,
    resolved: ResolvedTrustMetadata | undefined,
  ): TrustResult {
    let status = this.checkRecipientBinding(verificationStatus, toDID, toStableID);
    const acceptedInput = verificationStatus === "verified"
      || verificationStatus === "verified_legacy"
      || verificationStatus === "verified_custodial";
    const recipientBindingMismatch = acceptedInput && status === "identity_mismatch";
    if (resolved?.admittedSender) {
      const admitted = resolved.admittedSender;
      if (!acceptedInput || recipientBindingMismatch) return { status, stored: false };
      if (admitted.did !== fromDID || admitted.stableID !== (fromStableID || "")) return { status: "verification_stale", stored: false };
      return { status: admitted.status, stored: false };
    }
    if (resolved?.receivedLocalSender) {
      const local = resolved.receivedLocalSender;
      if (!acceptedInput || recipientBindingMismatch) return { status, stored: false };
      if (local.did !== fromDID || fromStableID) return { status: "verification_stale", stored: false };
      return { status: local.status, stored: local.status === "verified" && rawAddress.includes("/")
        ? store.removeAddresses([rawAddress]) : false };
    }
    if (resolved?.receivedSender) {
      const received = resolved.receivedSender;
      if (!acceptedInput || recipientBindingMismatch || !fromDID) return { status, stored: false };
      if (received.fromDID !== fromDID || received.stableID !== fromStableID) {
        return { status: "verification_stale", stored: false };
      }
      if (received.status !== "verified" || !received.registryURL || !received.head) {
        return { status: received.status, stored: false };
      }
      try {
        const checkpoint = store.receivedIdentityCheckpoint(received.registryURL, received.stableID);
        if (!this.sameCheckpoint(checkpoint, received.checkpoint)) return { status: "verification_stale", stored: false };
        return { status: "verified", stored: store.advanceReceivedIdentityCheckpoint(
          received.registryURL, received.stableID, received.head) };
      } catch (error) {
        console.error("aweb: received sender checkpoint unavailable:", error);
        return { status: "verification_stale", stored: false };
      }
    }
    if (!status || !rawAddress.trim()) return { status, stored: false };

    const acceptedSignature = status === "verified" || status === "verified_legacy" || status === "verified_custodial";
    if (!acceptedSignature || recipientBindingMismatch || !fromDID) return { status, stored: false };

    const trustAddress = this.canonicalTrustAddress(rawAddress);
    const meta = resolved?.meta || this.unavailableAgentMeta();
    if (!meta.resolved) return this.unresolvedMetadataResult(meta);

    if (this.teamRosterAliasReference(rawAddress.trim()) !== undefined && fromDID) {
      if (meta.identityScope === "local") {
        return this.verifyResolvedLocalSender(store, rawAddress.trim(), trustAddress, fromDID, meta, status);
      }
      if (!fromStableID) return { status: "identity_mismatch", stored: false };
    }

    const registryCheck = this.applyPreparedStableIdentityRegistry(
      store,
      status,
      fromDID,
      fromStableID,
      resolved?.stableIdentityCheck,
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
      && fromDID
      && this.teamRosterAliasReference(rawAddress.trim()) !== undefined
      && !fromStableID?.startsWith("did:aw:")
    ) {
      const localResult = this.verifyLocalSenderAgainstResolvedMetadata(
        store,
        rawAddress.trim(),
        trustAddress,
        fromDID,
        meta,
      );
      return checkpointAdvanced ? { ...localResult, stored: true } : localResult;
    }
    return checkpointAdvanced ? { ...pinResult, stored: true } : pinResult;
  }

  private admittedSenderTrust(status: VerificationStatus | undefined, stableID: string | undefined, context: ResolveTrustContext): VerificationStatus | undefined {
    if (status !== "verified" && status !== "verified_legacy" && status !== "verified_custodial") return status;
    const a = context.senderMembership!.admission!;
    if (context.projectedSenderDID && context.projectedSenderDID !== context.fromDID && context.projectedSenderDID !== stableID) return "identity_mismatch";
    if (a.outcome === "unrecorded") return status;
    if (a.outcome === "failed") return "identity_mismatch";
    if (a.outcome !== "verified" && a.outcome !== "verified_legacy") return "verification_stale";
    if (!a.message_id || a.message_id !== context.messageID) return "verification_stale";
    if (a.did_key !== context.fromDID || (stableID && a.did_aw !== stableID)
        || (context.senderTeamID && context.senderTeamID !== a.team_id)) return "identity_mismatch";
    return status;
  }

  private prepareReceivedLocalSender(status: VerificationStatus | undefined, context: ResolveTrustContext)
    : { did: string; status: VerificationStatus } | undefined {
    const member = context.senderMembership;
    const selected = this.teamID;
    const namespace = (team: string) => {
      const parts = team.split(":");
      return parts.length === 2 && parts[0] && parts[1] ? parts[1] : "";
    };
    const protectedTeam = context.senderTeamID || "";
    const address = context.verificationAddress.trim();
    const addressNamespace = address.includes("/") ? address.split("/")[0] : "";
    const referenceMatches = (team: string) => addressNamespace === team || addressNamespace === namespace(team);
    const crossTeam = selected && ((member?.team_id && member.team_id !== selected)
      || (protectedTeam && protectedTeam !== selected)
      || (addressNamespace && !referenceMatches(selected)));
    if (!crossTeam) return;
    const result = { did: context.fromDID || "", status: status || "unverified" };
    if (!["verified", "verified_legacy", "verified_custodial"].includes(result.status)) return result;
    result.status = "verification_stale";
    if (!member) return result;
    if (member.member_did_aw || member.state === "inactive"
      || (protectedTeam && member.team_id && protectedTeam !== member.team_id)
      || (addressNamespace && member.team_id && !referenceMatches(member.team_id))
      || (context.projectedSenderDID && context.projectedSenderDID !== context.fromDID)) {
      result.status = "identity_mismatch";
      return result;
    }
    if (member.state !== "active" || !namespace(member.team_id) || !context.projectedSenderDID || !context.fromDID) return result;
    try { extractPublicKey(context.fromDID); } catch { result.status = "identity_mismatch"; return result; }
    result.status = "verified";
    return result;
  }

  private async prepareReceivedSender(
    status: VerificationStatus | undefined, stableID: string, context: ResolveTrustContext,
  ): Promise<ReceivedSenderCheck> {
    const check: ReceivedSenderCheck = { fromDID: context.fromDID || "", stableID, status: status || "unverified" };
    if (!["verified", "verified_legacy", "verified_custodial"].includes(check.status) || !context.fromDID) return check;
    const membership = context.senderMembership;
    check.status = "verification_stale";
    if (!membership || membership.state === "unknown") return check;
    if (membership.state !== "active" || membership.member_did_aw !== stableID) {
      check.status = "identity_mismatch";
      return check;
    }
    if (!this.teamID || membership.team_id !== this.teamID) return check;
    const verified = await this.registry.verifyReceivedIdentity(this.teamID, stableID, context.fromDID, registryURL => {
      const head = context.pinStore.receivedIdentityCheckpoint(registryURL, stableID);
      check.checkpoint = head;
      return head;
    });
    if (verified.result.error) console.error("aweb: received sender identity verification:", verified.result.error);
    if (verified.result.outcome === "HARD_ERROR") check.status = "identity_mismatch";
    if (verified.result.outcome === "OK_VERIFIED" && verified.result.currentDidKey === context.fromDID
        && verified.result.verifiedHead) {
      check.status = "verified";
      check.registryURL = verified.registryURL;
      check.head = verified.result.verifiedHead;
    }
    return check;
  }

  private checkRecipientBinding(
    status: VerificationStatus | undefined,
    toDID: string | undefined,
    toStableID: string | undefined,
  ): VerificationStatus | undefined {
    if (status !== "verified" && status !== "verified_legacy" && status !== "verified_custodial") {
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

  private requiresStableIdentityCheck(
    status: VerificationStatus | undefined,
    fromDID: string | undefined,
    fromStableID: string | undefined,
  ): boolean {
    return status === "verified" && Boolean(fromDID) && Boolean(fromStableID?.startsWith("did:aw:"));
  }

  private unavailableAgentMeta(): AgentMeta {
    return {
      identityScope: "global",
      custody: "self",
      resolved: false,
      resolutionError: "unavailable",
    };
  }

  private unresolvedMetadataResult(meta: AgentMeta): TrustResult {
    return {
      status: meta.resolutionError === "not_found" ? "identity_mismatch" : "verification_stale",
      stored: false,
    };
  }

  private async prepareStableIdentityRegistry(
    store: PinStore,
    status: VerificationStatus | undefined,
    trustAddress: string,
    fromDID: string | undefined,
    fromStableID: string | undefined,
  ): Promise<PreparedStableIdentityCheck | undefined> {
    if (!this.requiresStableIdentityCheck(status, fromDID, fromStableID)) return undefined;

    // Registry verification can await DNS and HTTP. Seed it from one synchronous
    // checkpoint snapshot before that work, then revalidate the same values in
    // the trust critical section before applying the result.
    const checkpoint = this.pinCheckpoint(store, fromStableID!);
    this.seedVerifiedHeadFromPin(store, fromStableID!);
    return {
      checkpoint,
      result: await this.registry.verifyStableIdentity(trustAddress, fromStableID!, fromDID),
    };
  }

  private applyPreparedStableIdentityRegistry(
    store: PinStore,
    status: VerificationStatus | undefined,
    fromDID: string | undefined,
    fromStableID: string | undefined,
    prepared: PreparedStableIdentityCheck | undefined,
  ): {
    status: VerificationStatus | undefined;
    confirmedCurrentKey: boolean;
    verifiedHead?: VerifiedLogHead;
  } {
    if (!this.requiresStableIdentityCheck(status, fromDID, fromStableID)) {
      return { status, confirmedCurrentKey: false };
    }
    if (!prepared) return { status: "verification_stale", confirmedCurrentKey: false };

    // Evidence verified against an older anti-rollback anchor cannot be applied
    // after another decision advances or replaces that anchor. Degrade this
    // message rather than resolving again while holding the pin lock.
    const currentCheckpoint = this.pinCheckpoint(store, fromStableID!);
    if (!this.sameCheckpoint(currentCheckpoint, prepared.checkpoint)) {
      return { status: "verification_stale", confirmedCurrentKey: false };
    }

    const registryResult = prepared.result;
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

  private pinCheckpoint(store: PinStore, stableID: string): PinCheckpoint | undefined {
    const pin = store.pins.get(stableID);
    if (!pin?.log_seq || !pin.log_entry_hash) return undefined;
    return { seq: pin.log_seq, entryHash: pin.log_entry_hash };
  }

  private sameCheckpoint(
    left: PinCheckpoint | undefined,
    right: PinCheckpoint | undefined,
  ): boolean {
    if (!left || !right) return left === right;
    return left.seq === right.seq && left.entryHash === right.entryHash;
  }

  private seedVerifiedHeadFromPin(store: PinStore, stableID: string): void {
    const seed = (this.registry as { seedVerifiedHead?: (id: string, head: VerifiedLogHead) => void })
      .seedVerifiedHead;
    if (typeof seed !== "function") return;
    const checkpoint = this.pinCheckpoint(store, stableID);
    if (!checkpoint) return;
    const pin = store.pins.get(stableID)!;
    seed.call(this.registry, stableID, {
      seq: checkpoint.seq,
      entryHash: checkpoint.entryHash,
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
        // The steady state: an already-pinned sender presenting the key it is
        // pinned to. Nothing here is a continuity claim, so it commits only when
        // the store actually changed - otherwise every accepted message forces a
        // commit and the resident processes sharing this file spend their time
        // losing CAS races instead of delivering wakes (aweb-abdk). A store left
        // undurable by an earlier failure is still persisted: that is decided by
        // the caller, which commits on `stored || hasUndurableChanges()`.
        return { status, stored: store.recordVerifiedIdentity(pinKey, trustAddress, fromStableID, fromDID) };
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

  private verifyLocalSenderAgainstResolvedMetadata(
    store: PinStore,
    rawAddress: string,
    trustAddress: string,
    fromDID: string,
    resolved: AgentMeta,
  ): TrustResult {
    if (!resolved.resolved) return this.unresolvedMetadataResult(resolved);
    if (resolved.identityScope !== "local") {
      return { status: "identity_mismatch", stored: false };
    }
    return this.verifyResolvedLocalSender(store, rawAddress, trustAddress, fromDID, resolved, "verified");
  }

  private verifyResolvedLocalSender(
    store: PinStore,
    rawAddress: string,
    trustAddress: string,
    fromDID: string,
    fresh: AgentMeta,
    acceptedStatus: VerificationStatus,
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
    return { status: acceptedStatus, stored: removed };
  }

  private async resolveAgentMeta(address: string, forceRefresh = false): Promise<AgentMeta> {
    const rawAddress = address.trim();
    const trustAddress = this.canonicalTrustAddress(rawAddress);
    if (!trustAddress) {
      return { identityScope: "global", custody: "self", resolved: false };
    }
    const cached = this.metaCache.get(trustAddress);
    if (!forceRefresh && cached && this.now() <= cached.expiresAt) return cached.meta;

    try {
      const identity = await this.resolveIdentity(rawAddress, forceRefresh);
      const meta: AgentMeta = {
        did: identity.did,
        identityScope: identity.identityScope,
        custody: identity.custody || "self",
        controllerDid: identity.controllerDid,
        resolved: true,
      };
      this.metaCache.set(trustAddress, {
        meta,
        expiresAt: this.now() + AGENT_META_CACHE_TTL_MS,
      });
      return meta;
    } catch (error) {
      const statusCode = (error as { statusCode?: unknown } | undefined)?.statusCode;
      const meta: AgentMeta = {
        identityScope: "global",
        custody: "self",
        resolved: false,
        resolutionError: statusCode === 404 ? "not_found" : "unavailable",
      };
      this.metaCache.set(trustAddress, {
        meta,
        expiresAt: this.now() + this.jitteredTTL(
          AGENT_META_FAILURE_CACHE_MIN_MS,
          AGENT_META_FAILURE_CACHE_JITTER_MS,
        ),
      });
      return meta;
    }
  }

  private jitteredTTL(minimum: number, jitter: number): number {
    const random = Math.max(0, Math.min(0.999999999, this.random()));
    return minimum + Math.floor(random * jitter);
  }

  private teamRosterAliasReference(address: string): string | undefined {
    const client = this.client as APIClient & { hasTeamCertificateAuth?: (teamID: string) => boolean };
    return teamRosterAliasReference(
      address,
      this.teamID,
      typeof client.hasTeamCertificateAuth === "function",
    );
  }

  private async resolveIdentity(address: string, forceRefresh = false): Promise<ResolvedIdentity> {
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
    if (!(this.client.hasTeamRosterAuth?.(this.teamID) ?? this.client.hasTeamCertificateAuth(this.teamID))) {
      throw new Error("team roster resolution requires authenticated team access");
    }

    const roster = await this.resolveAuthenticatedTeamRoster(forceRefresh);
    const response = (roster.agents || []).find((agent) => (agent.alias || "").trim() === localAlias);
    if (!response) {
      const qualifiedTeamPrefix = `${this.teamID.toLowerCase()}/`;
      // A forced refresh was selected for a cached local key or absent alias.
      // Its projected domain address must not fall through to global authority
      // when the authenticated roster says that local member is gone.
      if (!forceRefresh && trimmed.includes("/") && !trimmed.toLowerCase().startsWith(qualifiedTeamPrefix)) {
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

  private async resolveAuthenticatedTeamRoster(forceRefresh = false): Promise<LocalAgentsResponse> {
    const cached = this.teamRosterCache;
    if (cached && this.now() <= cached.expiresAt) {
      if ("error" in cached) throw cached.error;
      if (!forceRefresh) return cached.roster;
    }
    if (this.teamRosterRequest) return this.teamRosterRequest;

    const read = forceRefresh && typeof this.client.getFresh === "function"
      ? this.client.getFresh<LocalAgentsResponse>("/v1/agents")
      : this.client.get<LocalAgentsResponse>("/v1/agents");
    const request = read.then((roster) => {
      if ((roster.team_id || "").trim() !== this.teamID) {
        throw new Error("team roster response does not match the authenticated team");
      }
      return roster;
    });
    this.teamRosterRequest = request;
    try {
      const roster = await request;
      this.teamRosterCache = {
        roster,
        expiresAt: this.now() + TEAM_ROSTER_CACHE_TTL_MS,
      };
      return roster;
    } catch (error) {
      // A shared failure needs a short quiet interval too. Starting it when the
      // request settles ensures a full client timeout cannot consume the backoff.
      this.teamRosterCache = {
        error,
        expiresAt: this.now() + this.jitteredTTL(
          TEAM_ROSTER_FAILURE_BACKOFF_MIN_MS,
          TEAM_ROSTER_FAILURE_BACKOFF_JITTER_MS,
        ),
      };
      throw error;
    } finally {
      if (this.teamRosterRequest === request) this.teamRosterRequest = undefined;
    }
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
