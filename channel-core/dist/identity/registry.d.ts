export declare const DEFAULT_AWID_REGISTRY_URL = "https://api.awid.ai";
export interface DomainAuthority {
    controllerDid: string;
    registryURL: string;
    dnsName: string;
    inherited: boolean;
}
export interface DidKeyEvidence {
    seq: number;
    operation: string;
    previous_did_key?: string | null;
    new_did_key: string;
    prev_entry_hash?: string | null;
    entry_hash: string;
    state_hash: string;
    authorized_by: string;
    signature: string;
    timestamp: string;
}
export interface DidKeyResolution {
    did_aw: string;
    current_did_key: string;
    log_head?: DidKeyEvidence | null;
}
export type StableIdentityOutcome = "OK_VERIFIED" | "OK_DEGRADED" | "HARD_ERROR";
export interface StableIdentityVerification {
    outcome: StableIdentityOutcome;
    currentDidKey?: string;
    error?: string;
}
export interface ResolvedRegistryIdentity {
    did: string;
    stableID: string;
    address: string;
    controllerDid: string;
    custody: "self";
    lifetime: "persistent";
}
interface VerifiedLogHead {
    seq: number;
    entryHash: string;
    stateHash: string;
    currentDidKey: string;
    fetchedAt: number;
}
type ResolveTxt = (hostname: string) => Promise<string[][]>;
interface RegistryResolverOptions {
    fallbackRegistryURL?: string;
}
export declare class RegistryResolver {
    private readonly fetchImpl;
    private readonly resolveTxtImpl;
    private readonly now;
    private registryCache;
    private addressCache;
    private keyCache;
    private headCache;
    private readonly fallbackRegistryURL;
    constructor(fetchImpl?: typeof fetch, resolveTxtImpl?: ResolveTxt, now?: () => number, options?: RegistryResolverOptions);
    verifyStableIdentity(address: string, stableID: string): Promise<StableIdentityVerification>;
    resolveAddressIdentity(address: string): Promise<{
        did: string;
        stableID: string;
    }>;
    resolveIdentity(address: string): Promise<ResolvedRegistryIdentity>;
    discoverRegistry(domain: string): Promise<string>;
    private discoverAuthority;
    private resolveAddress;
    private resolveDidKey;
    private getJSON;
}
export declare function discoverAuthoritativeRegistry(domain: string, resolveTxtImpl?: ResolveTxt): Promise<DomainAuthority>;
export declare function parseAwidTXTRecord(record: string, dnsName: string): DomainAuthority;
export declare function awidTXTName(domain: string): string;
export declare function candidateDomainsForLookup(domain: string, allowAncestors: boolean): string[];
export declare function registeredDomainBoundary(domain: string): string;
export declare function verifyDidKeyResolution(resolution: DidKeyResolution, cached: VerifiedLogHead | undefined, nowMs: number): {
    outcome: StableIdentityOutcome;
    nextHead?: VerifiedLogHead;
    error?: string;
};
export declare function canonicalDidLogPayload(didAW: string, head: DidKeyEvidence): string;
export {};
