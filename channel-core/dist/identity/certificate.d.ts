export interface TeamCertificate {
    version: number;
    certificate_id: string;
    team_id: string;
    team_did_key: string;
    member_did_key: string;
    member_did_aw?: string;
    member_address?: string;
    alias: string;
    lifetime: string;
    issued_at: string;
    signature: string;
}
export declare function loadTeamCertificate(path: string): Promise<TeamCertificate>;
export declare function encodeTeamCertificateHeader(cert: TeamCertificate): string;
