export interface AgentConfig {
    baseURL: string;
    did: string;
    stableID: string;
    address: string;
    alias: string;
    teamID: string;
    registryURL: string;
    signingKey: Uint8Array;
    teamCertificateHeader: string;
}
export declare function resolveConfig(workdir: string): Promise<AgentConfig>;
