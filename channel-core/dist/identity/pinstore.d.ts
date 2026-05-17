export type PinResult = "ok" | "new" | "mismatch" | "skipped";
export interface Pin {
    address: string;
    handle: string;
    stable_id?: string;
    did_key?: string;
    first_seen: string;
    last_seen: string;
    server: string;
}
export declare class PinStore {
    pins: Map<string, Pin>;
    addresses: Map<string, string>;
    /** Check whether a DID matches the stored pin for an address. */
    checkPin(address: string, did: string, lifetime: string): PinResult;
    /** Record or update a TOFU pin. */
    storePin(did: string, address: string, handle: string, server: string): void;
    removeAddress(address: string): boolean;
    save(path: string): Promise<void>;
    /** Serialize to YAML (compatible with Go's known_agents.yaml). */
    toYAML(): string;
    /** Deserialize from YAML. */
    static fromYAML(content: string): PinStore;
}
