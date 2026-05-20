export type CertificateIdentityScope = "global" | "local";
export type LegacyCertificateLifetime = "persistent" | "ephemeral";
export interface TeamCertificate {
    version: number;
    certificate_id: string;
    team_id: string;
    team_did_key: string;
    member_did_key: string;
    member_did_aw?: string;
    member_address?: string;
    alias: string;
    identity_scope?: CertificateIdentityScope;
    /** Legacy certificate field accepted for compatibility with existing team certs. */
    lifetime?: LegacyCertificateLifetime;
    issued_at: string;
    signature: string;
}
export declare function certificateIdentityScope(cert: Pick<TeamCertificate, "identity_scope" | "lifetime">): CertificateIdentityScope;
export declare function loadTeamCertificate(path: string): Promise<TeamCertificate>;
export declare function encodeTeamCertificateHeader(cert: TeamCertificate): string;
