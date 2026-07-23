import type { APIClient } from "../api/client.js";
import type { VerificationStatus } from "./signing.js";
import { RegistryResolver } from "./registry.js";
import { PinStore, type IdentityScope } from "./pinstore.js";
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
export interface TrustResult {
    status: VerificationStatus | undefined;
    stored: boolean;
}
export declare function normalizeIdentityScope(identityScope: string | undefined, legacyLifetime: string | undefined, defaultScope: IdentityScope): IdentityScope;
export declare class SenderTrustManager {
    private readonly client;
    private readonly registry;
    private readonly teamID;
    private readonly selfDid;
    private readonly selfStableID;
    private readonly metaCache;
    constructor(client: APIClient, registry: RegistryResolver, teamID: string, selfDid: string, selfStableID?: string);
    normalizeTrust(store: PinStore, verificationStatus: VerificationStatus | undefined, rawAddress: string, fromDID: string | undefined, fromStableID: string | undefined, toDID: string | undefined, toStableID: string | undefined, rotationAnnouncement?: RotationAnnouncement, replacementAnnouncement?: ReplacementAnnouncement, verificationAddress?: string): Promise<TrustResult>;
    private checkRecipientBinding;
    private checkStableIdentityRegistry;
    private checkTOFUPinWithMeta;
    private verifyRotationAnnouncement;
    private verifyReplacementAnnouncement;
    private canonicalTrustAddress;
    private reconcileLocalMismatch;
    private resolveAgentMeta;
    private resolveIdentity;
}
export declare function canonicalRotationJSON(oldDID: string, newDID: string, timestamp: string): string;
export declare function canonicalReplacementJSON(address: string, controllerDID: string, oldDID: string, newDID: string, timestamp: string): string;
