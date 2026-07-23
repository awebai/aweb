import { APIClient } from "./api/client.js";
import { type AgentEvent } from "./api/events.js";
import { PinStore } from "./identity/pinstore.js";
import { RegistryResolver } from "./identity/registry.js";
import { SenderTrustManager } from "./identity/trust.js";
import type { VerificationStatus } from "./identity/signing.js";
import { type LocalDecryptProvider } from "./local_aw.js";
export declare const DEFAULT_PIN_STORE_PATH: string;
export declare const DEFAULT_DELIVERY_STORE_PATH: string;
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
    deliveryStore?: DeliveryStore;
    localDecrypt?: LocalDecryptProvider;
    workdir?: string;
    awCommand?: string;
    log?: (message: string) => void;
}
export declare function loadPinStore(path?: string): Promise<PinStore>;
export declare class DeliveryStore {
    private readonly path;
    private entries;
    private constructor();
    static load(path?: string): Promise<DeliveryStore>;
    has(key: string): boolean;
    mark(key: string): void;
    save(): Promise<void>;
    private prune;
}
export declare function resolveRegistryFallbackURL(identityRegistryURL?: string): string | undefined;
export declare function createRegistryResolver(registryURL?: string): RegistryResolver;
export declare function createChannelClient(config: {
    baseURL: string;
    did: string;
    stableID: string;
    signingKey: Uint8Array;
    teamID: string;
    teamCertificateHeader: string;
}): APIClient;
export declare function startChannelLoop(options: ChannelLoopOptions): Promise<void>;
export declare function consumeAgentEvents(options: Omit<ChannelLoopOptions, "signal" | "log">, dispatched: Set<string>, events: AsyncIterable<AgentEvent>, log?: (message: string) => void): Promise<void>;
export declare function dispatchAgentEvent(options: Omit<ChannelLoopOptions, "signal" | "log">, dispatched: Set<string>, event: AgentEvent): Promise<void>;
export declare function isTrustedVerificationStatus(status: VerificationStatus | undefined): boolean;
export declare function trustWarningLine(status: VerificationStatus | undefined): string;
export declare function formatAwakeningForAgent(awakening: ChannelAwakening): string;
