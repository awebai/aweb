import { readFile } from "node:fs/promises";

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

export function certificateIdentityScope(cert: Pick<TeamCertificate, "identity_scope" | "lifetime">): CertificateIdentityScope {
  if (cert.identity_scope === "global" || cert.identity_scope === "local") return cert.identity_scope;
  if (cert.lifetime === "persistent") return "global";
  if (cert.lifetime === "ephemeral") return "local";
  return "local";
}

export async function loadTeamCertificate(path: string): Promise<TeamCertificate> {
  const content = await readFile(path, "utf-8");
  return JSON.parse(content) as TeamCertificate;
}

export function encodeTeamCertificateHeader(cert: TeamCertificate): string {
  return Buffer.from(JSON.stringify(cert), "utf-8").toString("base64");
}
